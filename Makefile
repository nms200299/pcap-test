#############################################################################
# Makefile for building: pcap-test
# Generated by qmake (3.1) (Qt 5.15.0)
# Project:  ../Desktop/pcap-test.pro
# Template: app
# Command: /home/kali/Qt/5.15.0/gcc_64/bin/qmake -o Makefile ../Desktop/pcap-test.pro -spec linux-g++ CONFIG+=debug CONFIG+=qml_debug
#############################################################################

MAKEFILE      = Makefile

EQ            = =

####### Compiler, tools and options

CC            = gcc
CXX           = g++
DEFINES       = -DQT_QML_DEBUG
CFLAGS        = -pipe -g -Wall -Wextra -fPIC $(DEFINES)
CXXFLAGS      = -pipe -g -std=gnu++11 -Wall -Wextra -fPIC $(DEFINES)
INCPATH       = -I../Desktop -I. -I../Qt/5.15.0/gcc_64/mkspecs/linux-g++
QMAKE         = /home/kali/Qt/5.15.0/gcc_64/bin/qmake
DEL_FILE      = rm -f
CHK_DIR_EXISTS= test -d
MKDIR         = mkdir -p
COPY          = cp -f
COPY_FILE     = cp -f
COPY_DIR      = cp -f -R
INSTALL_FILE  = install -m 644 -p
INSTALL_PROGRAM = install -m 755 -p
INSTALL_DIR   = cp -f -R
QINSTALL      = /home/kali/Qt/5.15.0/gcc_64/bin/qmake -install qinstall
QINSTALL_PROGRAM = /home/kali/Qt/5.15.0/gcc_64/bin/qmake -install qinstall -exe
DEL_FILE      = rm -f
SYMLINK       = ln -f -s
DEL_DIR       = rmdir
MOVE          = mv -f
TAR           = tar -cf
COMPRESS      = gzip -9f
DISTNAME      = pcap-test1.0.0
DISTDIR = /home/kali/build-pcap-test-Desktop_Qt_5_15_0_GCC_64bit-Debug/.tmp/pcap-test1.0.0
LINK          = g++
LFLAGS        = 
LIBS          = $(SUBLIBS) -lpcap   
AR            = ar cqs
RANLIB        = 
SED           = sed
STRIP         = strip

####### Output directory

OBJECTS_DIR   = ./

####### Files

SOURCES       = ../Desktop/main.cpp 
OBJECTS       = main.o
DIST          = ../Qt/5.15.0/gcc_64/mkspecs/features/spec_pre.prf \
		../Qt/5.15.0/gcc_64/mkspecs/common/unix.conf \
		../Qt/5.15.0/gcc_64/mkspecs/common/linux.conf \
		../Qt/5.15.0/gcc_64/mkspecs/common/sanitize.conf \
		../Qt/5.15.0/gcc_64/mkspecs/common/gcc-base.conf \
		../Qt/5.15.0/gcc_64/mkspecs/common/gcc-base-unix.conf \
		../Qt/5.15.0/gcc_64/mkspecs/common/g++-base.conf \
		../Qt/5.15.0/gcc_64/mkspecs/common/g++-unix.conf \
		../Qt/5.15.0/gcc_64/mkspecs/qconfig.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_3danimation.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_3danimation_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_3dcore.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_3dcore_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_3dextras.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_3dextras_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_3dinput.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_3dinput_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_3dlogic.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_3dlogic_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_3dquick.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_3dquick_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_3dquickanimation.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_3dquickanimation_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_3dquickextras.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_3dquickextras_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_3dquickinput.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_3dquickinput_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_3dquickrender.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_3dquickrender_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_3dquickscene2d.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_3dquickscene2d_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_3drender.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_3drender_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_accessibility_support_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_bluetooth.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_bluetooth_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_bootstrap_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_concurrent.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_concurrent_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_core.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_core_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_dbus.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_dbus_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_designer.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_designer_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_designercomponents_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_devicediscovery_support_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_edid_support_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_egl_support_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_eglfs_kms_support_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_eglfsdeviceintegration_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_eventdispatcher_support_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_fb_support_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_fontdatabase_support_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_gamepad.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_gamepad_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_glx_support_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_gui.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_gui_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_help.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_help_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_input_support_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_kms_support_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_linuxaccessibility_support_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_location.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_location_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_multimedia.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_multimedia_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_multimediagsttools_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_multimediawidgets.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_multimediawidgets_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_network.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_network_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_nfc.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_nfc_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_opengl.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_opengl_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_openglextensions.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_openglextensions_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_packetprotocol_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_platformcompositor_support_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_positioning.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_positioning_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_positioningquick.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_positioningquick_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_printsupport.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_printsupport_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_qml.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_qml_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_qmldebug_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_qmldevtools_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_qmlmodels.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_qmlmodels_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_qmltest.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_qmltest_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_qmlworkerscript.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_qmlworkerscript_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_qtmultimediaquicktools_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_quick.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_quick_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_quickcontrols2.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_quickcontrols2_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_quickparticles_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_quickshapes_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_quicktemplates2.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_quicktemplates2_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_quickwidgets.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_quickwidgets_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_remoteobjects.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_remoteobjects_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_repparser.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_repparser_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_scxml.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_scxml_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_sensors.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_sensors_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_serialbus.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_serialbus_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_serialport.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_serialport_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_service_support_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_sql.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_sql_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_svg.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_svg_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_testlib.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_testlib_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_texttospeech.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_texttospeech_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_theme_support_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_uiplugin.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_uitools.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_uitools_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_vulkan_support_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_waylandclient.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_waylandclient_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_webchannel.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_webchannel_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_websockets.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_websockets_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_webview.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_webview_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_widgets.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_widgets_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_x11extras.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_x11extras_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_xcb_qpa_lib_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_xkbcommon_support_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_xml.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_xml_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_xmlpatterns.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_xmlpatterns_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/features/qt_functions.prf \
		../Qt/5.15.0/gcc_64/mkspecs/features/qt_config.prf \
		../Qt/5.15.0/gcc_64/mkspecs/linux-g++/qmake.conf \
		../Qt/5.15.0/gcc_64/mkspecs/features/spec_post.prf \
		../Qt/5.15.0/gcc_64/mkspecs/features/exclusive_builds.prf \
		../Qt/5.15.0/gcc_64/mkspecs/features/toolchain.prf \
		../Qt/5.15.0/gcc_64/mkspecs/features/default_pre.prf \
		../Qt/5.15.0/gcc_64/mkspecs/features/resolve_config.prf \
		../Qt/5.15.0/gcc_64/mkspecs/features/default_post.prf \
		../Qt/5.15.0/gcc_64/mkspecs/features/qml_debug.prf \
		../Qt/5.15.0/gcc_64/mkspecs/features/warn_on.prf \
		../Qt/5.15.0/gcc_64/mkspecs/features/qmake_use.prf \
		../Qt/5.15.0/gcc_64/mkspecs/features/file_copies.prf \
		../Qt/5.15.0/gcc_64/mkspecs/features/testcase_targets.prf \
		../Qt/5.15.0/gcc_64/mkspecs/features/exceptions.prf \
		../Qt/5.15.0/gcc_64/mkspecs/features/yacc.prf \
		../Qt/5.15.0/gcc_64/mkspecs/features/lex.prf \
		../Desktop/pcap-test.pro  ../Desktop/main.cpp
QMAKE_TARGET  = pcap-test
DESTDIR       = 
TARGET        = pcap-test


first: all
####### Build rules

pcap-test:  $(OBJECTS)  
	$(LINK) $(LFLAGS) -o $(TARGET) $(OBJECTS) $(OBJCOMP) $(LIBS)

Makefile: ../Desktop/pcap-test.pro ../Qt/5.15.0/gcc_64/mkspecs/linux-g++/qmake.conf ../Qt/5.15.0/gcc_64/mkspecs/features/spec_pre.prf \
		../Qt/5.15.0/gcc_64/mkspecs/common/unix.conf \
		../Qt/5.15.0/gcc_64/mkspecs/common/linux.conf \
		../Qt/5.15.0/gcc_64/mkspecs/common/sanitize.conf \
		../Qt/5.15.0/gcc_64/mkspecs/common/gcc-base.conf \
		../Qt/5.15.0/gcc_64/mkspecs/common/gcc-base-unix.conf \
		../Qt/5.15.0/gcc_64/mkspecs/common/g++-base.conf \
		../Qt/5.15.0/gcc_64/mkspecs/common/g++-unix.conf \
		../Qt/5.15.0/gcc_64/mkspecs/qconfig.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_3danimation.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_3danimation_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_3dcore.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_3dcore_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_3dextras.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_3dextras_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_3dinput.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_3dinput_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_3dlogic.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_3dlogic_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_3dquick.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_3dquick_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_3dquickanimation.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_3dquickanimation_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_3dquickextras.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_3dquickextras_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_3dquickinput.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_3dquickinput_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_3dquickrender.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_3dquickrender_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_3dquickscene2d.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_3dquickscene2d_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_3drender.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_3drender_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_accessibility_support_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_bluetooth.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_bluetooth_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_bootstrap_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_concurrent.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_concurrent_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_core.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_core_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_dbus.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_dbus_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_designer.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_designer_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_designercomponents_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_devicediscovery_support_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_edid_support_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_egl_support_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_eglfs_kms_support_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_eglfsdeviceintegration_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_eventdispatcher_support_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_fb_support_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_fontdatabase_support_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_gamepad.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_gamepad_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_glx_support_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_gui.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_gui_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_help.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_help_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_input_support_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_kms_support_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_linuxaccessibility_support_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_location.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_location_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_multimedia.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_multimedia_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_multimediagsttools_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_multimediawidgets.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_multimediawidgets_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_network.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_network_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_nfc.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_nfc_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_opengl.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_opengl_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_openglextensions.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_openglextensions_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_packetprotocol_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_platformcompositor_support_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_positioning.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_positioning_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_positioningquick.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_positioningquick_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_printsupport.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_printsupport_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_qml.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_qml_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_qmldebug_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_qmldevtools_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_qmlmodels.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_qmlmodels_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_qmltest.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_qmltest_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_qmlworkerscript.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_qmlworkerscript_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_qtmultimediaquicktools_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_quick.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_quick_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_quickcontrols2.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_quickcontrols2_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_quickparticles_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_quickshapes_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_quicktemplates2.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_quicktemplates2_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_quickwidgets.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_quickwidgets_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_remoteobjects.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_remoteobjects_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_repparser.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_repparser_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_scxml.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_scxml_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_sensors.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_sensors_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_serialbus.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_serialbus_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_serialport.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_serialport_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_service_support_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_sql.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_sql_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_svg.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_svg_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_testlib.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_testlib_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_texttospeech.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_texttospeech_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_theme_support_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_uiplugin.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_uitools.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_uitools_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_vulkan_support_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_waylandclient.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_waylandclient_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_webchannel.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_webchannel_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_websockets.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_websockets_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_webview.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_webview_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_widgets.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_widgets_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_x11extras.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_x11extras_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_xcb_qpa_lib_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_xkbcommon_support_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_xml.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_xml_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_xmlpatterns.pri \
		../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_xmlpatterns_private.pri \
		../Qt/5.15.0/gcc_64/mkspecs/features/qt_functions.prf \
		../Qt/5.15.0/gcc_64/mkspecs/features/qt_config.prf \
		../Qt/5.15.0/gcc_64/mkspecs/linux-g++/qmake.conf \
		../Qt/5.15.0/gcc_64/mkspecs/features/spec_post.prf \
		../Qt/5.15.0/gcc_64/mkspecs/features/exclusive_builds.prf \
		../Qt/5.15.0/gcc_64/mkspecs/features/toolchain.prf \
		../Qt/5.15.0/gcc_64/mkspecs/features/default_pre.prf \
		../Qt/5.15.0/gcc_64/mkspecs/features/resolve_config.prf \
		../Qt/5.15.0/gcc_64/mkspecs/features/default_post.prf \
		../Qt/5.15.0/gcc_64/mkspecs/features/qml_debug.prf \
		../Qt/5.15.0/gcc_64/mkspecs/features/warn_on.prf \
		../Qt/5.15.0/gcc_64/mkspecs/features/qmake_use.prf \
		../Qt/5.15.0/gcc_64/mkspecs/features/file_copies.prf \
		../Qt/5.15.0/gcc_64/mkspecs/features/testcase_targets.prf \
		../Qt/5.15.0/gcc_64/mkspecs/features/exceptions.prf \
		../Qt/5.15.0/gcc_64/mkspecs/features/yacc.prf \
		../Qt/5.15.0/gcc_64/mkspecs/features/lex.prf \
		../Desktop/pcap-test.pro
	$(QMAKE) -o Makefile ../Desktop/pcap-test.pro -spec linux-g++ CONFIG+=debug CONFIG+=qml_debug
../Qt/5.15.0/gcc_64/mkspecs/features/spec_pre.prf:
../Qt/5.15.0/gcc_64/mkspecs/common/unix.conf:
../Qt/5.15.0/gcc_64/mkspecs/common/linux.conf:
../Qt/5.15.0/gcc_64/mkspecs/common/sanitize.conf:
../Qt/5.15.0/gcc_64/mkspecs/common/gcc-base.conf:
../Qt/5.15.0/gcc_64/mkspecs/common/gcc-base-unix.conf:
../Qt/5.15.0/gcc_64/mkspecs/common/g++-base.conf:
../Qt/5.15.0/gcc_64/mkspecs/common/g++-unix.conf:
../Qt/5.15.0/gcc_64/mkspecs/qconfig.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_3danimation.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_3danimation_private.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_3dcore.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_3dcore_private.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_3dextras.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_3dextras_private.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_3dinput.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_3dinput_private.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_3dlogic.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_3dlogic_private.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_3dquick.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_3dquick_private.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_3dquickanimation.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_3dquickanimation_private.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_3dquickextras.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_3dquickextras_private.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_3dquickinput.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_3dquickinput_private.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_3dquickrender.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_3dquickrender_private.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_3dquickscene2d.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_3dquickscene2d_private.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_3drender.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_3drender_private.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_accessibility_support_private.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_bluetooth.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_bluetooth_private.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_bootstrap_private.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_concurrent.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_concurrent_private.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_core.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_core_private.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_dbus.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_dbus_private.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_designer.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_designer_private.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_designercomponents_private.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_devicediscovery_support_private.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_edid_support_private.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_egl_support_private.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_eglfs_kms_support_private.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_eglfsdeviceintegration_private.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_eventdispatcher_support_private.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_fb_support_private.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_fontdatabase_support_private.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_gamepad.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_gamepad_private.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_glx_support_private.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_gui.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_gui_private.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_help.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_help_private.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_input_support_private.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_kms_support_private.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_linuxaccessibility_support_private.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_location.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_location_private.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_multimedia.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_multimedia_private.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_multimediagsttools_private.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_multimediawidgets.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_multimediawidgets_private.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_network.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_network_private.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_nfc.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_nfc_private.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_opengl.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_opengl_private.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_openglextensions.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_openglextensions_private.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_packetprotocol_private.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_platformcompositor_support_private.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_positioning.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_positioning_private.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_positioningquick.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_positioningquick_private.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_printsupport.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_printsupport_private.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_qml.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_qml_private.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_qmldebug_private.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_qmldevtools_private.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_qmlmodels.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_qmlmodels_private.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_qmltest.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_qmltest_private.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_qmlworkerscript.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_qmlworkerscript_private.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_qtmultimediaquicktools_private.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_quick.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_quick_private.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_quickcontrols2.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_quickcontrols2_private.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_quickparticles_private.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_quickshapes_private.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_quicktemplates2.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_quicktemplates2_private.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_quickwidgets.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_quickwidgets_private.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_remoteobjects.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_remoteobjects_private.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_repparser.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_repparser_private.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_scxml.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_scxml_private.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_sensors.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_sensors_private.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_serialbus.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_serialbus_private.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_serialport.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_serialport_private.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_service_support_private.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_sql.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_sql_private.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_svg.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_svg_private.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_testlib.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_testlib_private.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_texttospeech.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_texttospeech_private.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_theme_support_private.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_uiplugin.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_uitools.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_uitools_private.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_vulkan_support_private.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_waylandclient.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_waylandclient_private.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_webchannel.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_webchannel_private.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_websockets.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_websockets_private.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_webview.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_webview_private.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_widgets.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_widgets_private.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_x11extras.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_x11extras_private.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_xcb_qpa_lib_private.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_xkbcommon_support_private.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_xml.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_xml_private.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_xmlpatterns.pri:
../Qt/5.15.0/gcc_64/mkspecs/modules/qt_lib_xmlpatterns_private.pri:
../Qt/5.15.0/gcc_64/mkspecs/features/qt_functions.prf:
../Qt/5.15.0/gcc_64/mkspecs/features/qt_config.prf:
../Qt/5.15.0/gcc_64/mkspecs/linux-g++/qmake.conf:
../Qt/5.15.0/gcc_64/mkspecs/features/spec_post.prf:
../Qt/5.15.0/gcc_64/mkspecs/features/exclusive_builds.prf:
../Qt/5.15.0/gcc_64/mkspecs/features/toolchain.prf:
../Qt/5.15.0/gcc_64/mkspecs/features/default_pre.prf:
../Qt/5.15.0/gcc_64/mkspecs/features/resolve_config.prf:
../Qt/5.15.0/gcc_64/mkspecs/features/default_post.prf:
../Qt/5.15.0/gcc_64/mkspecs/features/qml_debug.prf:
../Qt/5.15.0/gcc_64/mkspecs/features/warn_on.prf:
../Qt/5.15.0/gcc_64/mkspecs/features/qmake_use.prf:
../Qt/5.15.0/gcc_64/mkspecs/features/file_copies.prf:
../Qt/5.15.0/gcc_64/mkspecs/features/testcase_targets.prf:
../Qt/5.15.0/gcc_64/mkspecs/features/exceptions.prf:
../Qt/5.15.0/gcc_64/mkspecs/features/yacc.prf:
../Qt/5.15.0/gcc_64/mkspecs/features/lex.prf:
../Desktop/pcap-test.pro:
qmake: FORCE
	@$(QMAKE) -o Makefile ../Desktop/pcap-test.pro -spec linux-g++ CONFIG+=debug CONFIG+=qml_debug

qmake_all: FORCE


all: Makefile pcap-test

dist: distdir FORCE
	(cd `dirname $(DISTDIR)` && $(TAR) $(DISTNAME).tar $(DISTNAME) && $(COMPRESS) $(DISTNAME).tar) && $(MOVE) `dirname $(DISTDIR)`/$(DISTNAME).tar.gz . && $(DEL_FILE) -r $(DISTDIR)

distdir: FORCE
	@test -d $(DISTDIR) || mkdir -p $(DISTDIR)
	$(COPY_FILE) --parents $(DIST) $(DISTDIR)/


clean: compiler_clean 
	-$(DEL_FILE) $(OBJECTS)
	-$(DEL_FILE) *~ core *.core


distclean: clean 
	-$(DEL_FILE) $(TARGET) 
	-$(DEL_FILE) .qmake.stash
	-$(DEL_FILE) Makefile


####### Sub-libraries

check: first

benchmark: first

compiler_yacc_decl_make_all:
compiler_yacc_decl_clean:
compiler_yacc_impl_make_all:
compiler_yacc_impl_clean:
compiler_lex_make_all:
compiler_lex_clean:
compiler_clean: 

####### Compile

main.o: ../Desktop/main.cpp 
	$(CXX) -c $(CXXFLAGS) $(INCPATH) -o main.o ../Desktop/main.cpp

####### Install

install:  FORCE

uninstall:  FORCE

FORCE:

