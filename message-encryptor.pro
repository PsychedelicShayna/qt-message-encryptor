QT += core gui
greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = message-encryptor
TEMPLATE = app

DEFINES += QT_DEPRECATED_WARNINGS

CONFIG += c++17

SOURCES += \
        source/main.cxx \
        source/main_wnd.cxx

HEADERS += \
        source/main_wnd.hxx \
        dependencies/abstract-ossl.hxx

FORMS += \
        source/main_wnd.ui

win32 {
    LIBS += -L../../dependencies/lib/windows
    LIBS += -lwindows_openssl_abstraction_layer

    # OpenSSL Include directory.
    INCLUDEPATH += C:/OpenSSL-Win64/include/
    DEPENDPATH += C:/OpenSSL-Win64/include/

    # Separate Windows libraries that OpenSSL requires to link properly.
    LIBS += -lUser32 -lAdvapi32 -lCrypt32 -lWs2_32

    # OpenSSL Library directory.
    LIBS += -LC:/OpenSSL-Win64/lib/VC/static/

    # OpenSSL Static library linkage (debug/release).
    CONFIG(release, debug|release): LIBS += -llibcrypto64MD
    CONFIG(debug, debug|release): LIBS += -llibcrypto64MDd
}

macx {
    LIBS += -L../../dependencies/lib/osx
    LIBS += -losx_openssl_abstraction_layer


    INCLUDEPATH += /usr/local/include/
    DEPENDPATH += /usr/local/include/
    LIBS += -L/usr/local/lib/

    # libcrypto.a Should be in /usr/local/lib
    LIBS += -lcrypto

    target.path = /usr/lib
    INSTALLS += target
}

# Unix library linking, and include paths.
unix {    
    LIBS += -L../../dependencies/lib/linux
    LIBS += -llinux_openssl_abstraction_layer


    INCLUDEPATH += /usr/local/include/
    DEPENDPATH += /usr/local/include/
    LIBS += -L/usr/local/lib/

    # libcrypto.a Should be in /usr/local/lib
    LIBS += -lcrypto
}


# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target
