//
// Created by Constantin on 20/09/2025.
//

#include "gui.h"
#include <QPushButton>
#include <QApplication>
int create_gui(int argc, char *argv[]){
    QWidget *window;
    QApplication app(argc, argv);

    try {
        window = new QWidget();

        window->setWindowTitle("Indigo");
        window->show();
    }
    catch(const std::exception &e) {
        return -1;
    }

    return app.exec();
}
/////////////////////////////////////////////////////////
///                                                   ///
///                  THE_LOCK_SCREEN                  ///
///                                                   ///
/////////////////////////////////////////////////////////


////////////////////////////////////////////////////////////
///                                                      ///
///                  THE_MAIN_INTERFACE                  ///
///                                                      ///
////////////////////////////////////////////////////////////


///////////////////////////////////////////////////
///                                             ///
///                  UTILITIES                  ///
///                                             ///
///////////////////////////////////////////////////