# Copyright (c) 2018 The Lux developers

project(lux-qt)

# This ensure that AUTOMOC doesn't run on generated files.
cmake_policy(SET CMP0071 OLD)

include(BrewHelper)
find_brew_prefix(QT5_PREFIX qt5)
find_package(Qt5 COMPONENTS Widgets Network REQUIRED HINTS "${QT5_PREFIX}")

# Localisation
add_subdirectory(locale)

add_custom_command(OUTPUT temp_lux_locale.qrc
	COMMAND cmake
	ARGS
		-E copy
		"${CMAKE_CURRENT_SOURCE_DIR}/lux_locale.qrc"
		temp_lux_locale.qrc
	MAIN_DEPENDENCY lux_locale.qrc
	VERBATIM
)

add_custom_command(OUTPUT qrc_lux_locale.cpp
	COMMAND Qt5::rcc
	ARGS
		temp_lux_locale.qrc
		-name lux_locale
		-o qrc_lux_locale.cpp
	MAIN_DEPENDENCY temp_lux_locale.qrc
	DEPENDS locales
	VERBATIM
)

# UI elements
qt5_wrap_ui(UI_GENERATED_HEADERS
qt/forms/addressbookpage.ui
qt/forms/addtokenpage.ui
qt/forms/askpassphrasedialog.ui
qt/forms/callcontract.ui
qt/forms/bip38tooldialog.ui
qt/forms/coincontroldialog.ui
qt/forms/contractbookpage.ui
qt/forms/contractresult.ui
qt/forms/createcontract.ui
qt/forms/blockexplorer.ui
qt/forms/darksendconfig.ui
qt/forms/editaddressdialog.ui
qt/forms/editcontractinfodialog.ui
qt/forms/helpmessagedialog.ui
qt/forms/intro.ui
qt/forms/eula.ui
qt/forms/masternodemanager.ui
qt/forms/addeditluxnode.ui
qt/forms/lsrtoken.ui
qt/forms/luxnodeconfigdialog.ui
qt/forms/multisenddialog.ui
qt/forms/openuridialog.ui
qt/forms/optionsdialog.ui
qt/forms/overviewpage.ui
qt/forms/tradingdialog.ui
qt/forms/receivecoinsdialog.ui
qt/forms/receivetokenpage.ui
qt/forms/receiverequestdialog.ui
qt/forms/restoredialog.ui
qt/forms/rpcconsole.ui
qt/forms/sendcoinsdialog.ui
qt/forms/sendtokenpage.ui
qt/forms/sendcoinsentry.ui
qt/forms/sendtocontract.ui
qt/forms/signverifymessagedialog.ui
qt/forms/smartcontract.ui
qt/forms/tokendescdialog.ui
qt/forms/transactiondescdialog.ui
)

# Qt MOC
set(CMAKE_AUTOMOC ON)

# Handle qrc resources
qt5_add_resources(QRC_LUX_CPP lux.qrc)

# Do protobuf codegen
find_package(Protobuf REQUIRED)
protobuf_generate_cpp(PROTOBUF_SOURCES PROTOBUF_HEADERS paymentrequest.proto)

add_library(lux-qt-base
qt/bitcoinaddressvalidator.cpp
qt/bitcoinamountfield.cpp
qt/bitcoingui.cpp
qt/bitcoinunits.cpp
qt/blockexplorer.cpp
qt/clientmodel.cpp
qt/csvmodelwriter.cpp
qt/guiutil.cpp
qt/intro.cpp
qt/eula.cpp
qt/masternodemanager.cpp
qt/addeditluxnode.cpp
qt/luxnodeconfigdialog.cpp
qt/networkstyle.cpp
qt/token.cpp
qt/notificator.cpp
qt/optionsdialog.cpp
qt/optionsmodel.cpp
qt/peertablemodel.cpp
qt/platformstyle.cpp
qt/qvalidatedlineedit.cpp
qt/qvalidatedtextedit.cpp
qt/qvaluecombobox.cpp
qt/rpcconsole.cpp
qt/splashscreen.cpp
qt/tabbarinfo.cpp
qt/tokenitemmodel.cpp
qt/tokenamountfield.cpp
qt/trafficgraphwidget.cpp
qt/utilitydialog.cpp
qt/winshutdownmonitor.cpp

	# Handle ui files
	${UI_GENERATED_HEADERS}

	# Protobuf codegen
	${PROTOBUF_HEADERS}
	${PROTOBUF_SOURCES}

	# Translations
	${LUX_QM_FILES}

	# Handle qrc files
	${QRC_LUX_CPP}
	qrc_lux_locale.cpp
)

# Windows support
if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
	target_sources(lux-qt-base PRIVATE winshutdownmonitor.cpp)
endif()

target_include_directories(lux-qt-base
	PUBLIC
		.
		${CMAKE_CURRENT_BINARY_DIR}
		${CMAKE_CURRENT_BINARY_DIR}/forms
		${Protobuf_INCLUDE_DIRS}
	PRIVATE
		${OPENSSL_INCLUDE_DIR}
)

target_link_libraries(lux-qt-base
	server
	rpcclient
	Qt5::Widgets
	Qt5::Network
	${Protobuf_LIBRARIES}
)

if(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
	set_property(TARGET lux-qt-base PROPERTY AUTOMOC_MOC_OPTIONS "-DQ_OS_MAC")
endif()

# Wallet
if(BUILD_LUX_WALLET)
	target_sources(lux-qt-base
		PRIVATE
qt/abifunctionfield.cpp
qt/abiparam.cpp
qt/abiparamitem.cpp
qt/abiparamsfield.cpp
qt/addressbookpage.cpp
qt/addressfield.cpp
qt/qvalidatedtextedit.cpp
qt/qvalidatedlineedit.cpp
qt/createcontract.cpp
qt/addresstablemodel.cpp
qt/addtokenpage.cpp
qt/askpassphrasedialog.cpp
qt/bip38tooldialog.cpp
qt/blockexplorer.cpp
qt/callcontract.cpp
qt/coincontroldialog.cpp
qt/coincontroltreewidget.cpp
qt/contractabi.cpp
qt/contractbookpage.cpp
qt/contractresult.cpp
qt/contracttablemodel.cpp
qt/createcontract.cpp
qt/darksendconfig.cpp
qt/editaddressdialog.cpp
qt/execrpccommand.cpp
qt/editcontractinfodialog.cpp
qt/eventlog.cpp
qt/masternodemanager.cpp
qt/addeditluxnode.cpp
qt/luxnodeconfigdialog.cpp
qt/multisenddialog.cpp
qt/openuridialog.cpp
qt/overviewpage.cpp
qt/qcustomplot.cpp
qt/tradingdialog.cpp
qt/paymentrequestplus.cpp
qt/paymentserver.cpp
qt/lsrtoken.cpp
qt/receivecoinsdialog.cpp
qt/receiverequestdialog.cpp
qt/receivetokenpage.cpp
qt/recentrequeststablemodel.cpp
qt/restoredialog.cpp
qt/sendcoinsdialog.cpp
qt/sendcoinsentry.cpp
qt/sendtocontract.cpp
qt/sendtokenpage.cpp
qt/signverifymessagedialog.cpp
qt/smartcontract.cpp
qt/tokendescdialog.cpp
qt/tokenfilterproxy.cpp
qt/tokentransactionview.cpp
qt/tokentransactionrecord.cpp
qt/tokentransactiontablemodel.cpp
qt/tokentransactiondesc.cpp
qt/transactiondesc.cpp
qt/transactiondescdialog.cpp
qt/transactionfilterproxy.cpp
qt/transactionrecord.cpp
qt/transactiontablemodel.cpp
qt/transactionview.cpp
qt/walletframe.cpp
qt/walletmodel.cpp
qt/walletmodeltransaction.cpp
qt/walletview.cpp
	)

	target_link_libraries(lux-qt-base wallet)

	# Dependencies
	# Support Brew OpenSSL on MacOS X
	include(BrewHelper)
	find_brew_prefix(OPENSSL_ROOT_DIR openssl)
	find_package(OpenSSL REQUIRED)
	target_link_libraries(lux-qt-base ${OPENSSL_CRYPTO_LIBRARY})
endif()
