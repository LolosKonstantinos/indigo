//
// Created by constantin on 8/26/26.
//

#ifndef INDIGO_QT_UI_GLOBAL_H
#define INDIGO_QT_UI_GLOBAL_H

#include <QtCore/qglobal.h>

#if defined(UNTITLED1_LIBRARY)
#define UNTITLED1_EXPORT Q_DECL_EXPORT
#else
#define UNTITLED1_EXPORT Q_DECL_IMPORT
#endif

#endif // INDIGO_QT_UI_GLOBAL_H
