#pragma once

#include <QtWidgets/QMainWindow>
#include "ui_AsmCodeRun.h"
#include <Windows.h>
#include <Tlhelp32.h>
#include <vector>
#include <string>
using namespace std;
class AsmCodeRun : public QMainWindow
{
	Q_OBJECT

public:
	AsmCodeRun(QWidget *parent = Q_NULLPTR);

private:
	bool PraseAsm(QString);
	bool RunShellCode();
	bool GetThreadIdByProcessId(int ProcessId, vector<unsigned int>& ThreadIdVector);
	bool InjectDllByApc(LPVOID Address, unsigned int ThreadId);
	bool GrantPriviledge(IN PWCHAR PriviledgeName);
private:
	Ui::AsmCodeRunClass ui;
	unsigned char* m_pHexBuffer;
	int m_nHexBufferLength;

private slots:
	bool ExchangeCodeClicked();
	bool RunCodeClicked();
};
