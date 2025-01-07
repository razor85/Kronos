/*	Copyright 2025 Romulo Leitão <abra185@gmail.com>

	This file is part of Yabause.

	Yabause is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation; either version 2 of the License, or
	(at your option) any later version.

	Yabause is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with Yabause; if not, write to the Free Software
	Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
*/

#include "Settings.h"
#include "UIDebugSH2.h"
#include "UIProfiler.h"

#include <QProcess>
#include <QString>
#include <QPushButton>
#include <QStandardItemModel>

namespace {

QString invokeAddr2LineAndFilt(u32 address, const QString& addr2line, const QString& elfPath, const QString& cppFilt) {
   if (addr2line.isEmpty() || elfPath.isEmpty()) {
      return "";
   }

   // The options are:
   //  -i --inlines           Unwind inlined functions
   //  -p --pretty-print      Make the output easier to read for humans
   //  -f --functions         Show function names
   //  -r --no-recurse-limit  Disable a limit on recursion whilst demangling
   //  -s --basenames         Strip directory names
   //  -e --exe=<executable>  Set the input file name (default is a.out)
   const QStringList arguments = { 
     QString("%1").arg(address, 8, 16, QChar('0')),
     "-i", "-p", "-f", "-r", "-s",
     "-e", elfPath
   };
 
   QProcess addr2lineProgram;
   addr2lineProgram.start(addr2line, arguments);
   addr2lineProgram.waitForFinished();

   const QByteArray pStdout = addr2lineProgram.readAllStandardOutput();
   if (addr2lineProgram.exitCode() == 0) {
      if (cppFilt.isEmpty())
      {
         QString result(pStdout);
         result.replace("\n", "");
         result.replace("\r", "");
         return result;
      }
      else {
         QStringList words = QString(pStdout).split(' ', QString::SkipEmptyParts);

         QString result;
         for (const QString& word : words) {
            QStringList cppfiltArgs;
            if (!word.startsWith("__"))
            {
              cppfiltArgs.append("-n");
            }
            cppfiltArgs.append(word);

            QProcess cppFiltProgram;
            cppFiltProgram.start(cppFilt, cppfiltArgs);
            cppFiltProgram.waitForFinished();

            if (cppFiltProgram.exitCode() == 0)
            {
              result += cppFiltProgram.readAllStandardOutput();
              result += " ";
            }
            else {
              result += word;
              result += " ";
            }
         }

         result.replace("\n", "");
         result.replace("\r", "");
         return result;
      }
   }

   return "";
}

}

UIProfiler::UIProfiler( YabauseThread *yabauseThread, QWidget* p )
	: QDialog( p )
{
   setupUi(this);
   mYabauseThread = yabauseThread;

   QStringList headers;
   headers << "Count"
           << "Time(ms)"
           << "Percent"
           << "Ptr(H)"
           << "Description";

   mItemModel = new QStandardItemModel();
   mItemModel->setSortRole(Qt::UserRole + 1);
   mItemModel->setColumnCount(headers.size());
   mItemModel->setHorizontalHeaderLabels(headers);

   twProfilerResults->setModel(mItemModel);

   twProfilerResults->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
   twProfilerResults->horizontalHeader()->setStretchLastSection(true);
   twProfilerResults->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);

   twProfilerResults->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);  // Count
   twProfilerResults->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);  // Time
   twProfilerResults->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);  // Percent
   twProfilerResults->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);  // Ptr
   twProfilerResults->horizontalHeader()->setSectionResizeMode(4, QHeaderView::Stretch);           // Description
   
   twProfilerResults->setAlternatingRowColors(true);

	QtYabause::retranslateWidget( this );

   if (mYabauseThread->init() == 0 && MSH2 && SSH2)
   {
      populateTable();
   }
}
   
void UIProfiler::addRow(u64 count, double timeMs, double percent, u32 ptrH, const QString &description)
{
   int row = mItemModel->rowCount();
   mItemModel->insertRow(row);

   // We do that so we can represent the numbers with 2 decimal places but keep their sort value.
   QStandardItem* timeItem = new QStandardItem(QString::number(timeMs, 'f', 2));
   timeItem->setData(timeMs, Qt::UserRole + 1);

   QStandardItem* percentItem = new QStandardItem(QString::number(percent, 'f', 2));
   timeItem->setData(percent, Qt::UserRole + 1);

   mItemModel->setItem(row, 0, new QStandardItem(QString::number(count)));
   mItemModel->setItem(row, 1, timeItem);
   mItemModel->setItem(row, 2, percentItem);
   mItemModel->setItem(row, 3, new QStandardItem(QString("0x%1").arg(ptrH, 8, 16, QChar('0'))));
   mItemModel->setItem(row, 4, new QStandardItem(description));
}

void UIProfiler::populateTable()
{
   Settings* settings = QtYabause::settings();
   QString addr2line = settings->value( "Debug/Addr2Line" ).toString();
   QString cppfilt = settings->value( "Debug/CppFilt" ).toString();
   QString elfFile = UIDebugSH2::findElfPath();

   double totalMasterTime = 0;
   double totalSlaveTime = 0;
   
   for (u32 i = 0; i < PROFILE_NUM_INFOS; ++i)
   {
      SH2_ProfilerInfo* infoM = &MSH2->profilerInfo.profile[i];
      if (infoM->count > 0)
      {
        totalMasterTime += infoM->time;
      }
      
      SH2_ProfilerInfo* infoS = &SSH2->profilerInfo.profile[i];
      if (infoS->count > 0)
      {
        totalSlaveTime += infoS->time;
      }
   }
   
   mItemModel->setRowCount(0);
   twProfilerResults->setSortingEnabled(false);

   for (u32 i = 0; i < PROFILE_NUM_INFOS; ++i)
   {
      // Master
      {
         SH2_ProfilerInfo* infoM = &MSH2->profilerInfo.profile[i];
         if (infoM->count > 0)
         {
            u32 address = MSH2->profilerInfo.startMonitorAddress + i;
            QString description = invokeAddr2LineAndFilt(address, addr2line, elfFile, cppfilt);

            addRow(infoM->count, infoM->time, (double)infoM->time / totalMasterTime,
              address, description);
         }
      }

      // Slave
      {
         SH2_ProfilerInfo* infoS = &SSH2->profilerInfo.profile[i];
         if (infoS->count > 0)
         {
            u32 address = SSH2->profilerInfo.startMonitorAddress + i;
            QString description = invokeAddr2LineAndFilt(address, addr2line, elfFile, cppfilt);
            addRow(infoS->count, infoS->time, (double)infoS->time / totalSlaveTime,
              address, description);
         }
      }
   }

   twProfilerResults->setSortingEnabled(true);
   twProfilerResults->sortByColumn(1, Qt::DescendingOrder); // Sort by Time(ms)
}

void UIProfiler::clearTable()
{
   for (u32 i = 0; i < PROFILE_NUM_INFOS; ++i)
   {
      SH2_ProfilerInfo* infoM = &MSH2->profilerInfo.profile[i];
      infoM->time = 0;
      infoM->count = 0;

      SH2_ProfilerInfo* infoS = &SSH2->profilerInfo.profile[i];
      infoS->time = 0;
      infoS->count = 0;
   }

   twProfilerResults->setSortingEnabled(false);
   mItemModel->setRowCount(0);
}

void UIProfiler::on_pbClearResults_clicked()
{
   clearTable();
}

void UIProfiler::accept()
{
   QDialog::accept();
}

void UIProfiler::reject()
{
   QDialog::reject();
}
