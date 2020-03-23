#include "AsmCodeRun.h"
#include <QtWidgets/QApplication>

int main(int argc, char *argv[])
{
	QApplication a(argc, argv);
	AsmCodeRun w;
	w.show();
	return a.exec();
}
