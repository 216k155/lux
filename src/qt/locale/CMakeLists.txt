# Copyright (c) 2018 The Bitcoin developers

project(lux-qt-locale)

include(BrewHelper)
find_brew_prefix(QT5_PREFIX qt5)

find_package(Qt5LinguistTools HINTS "${QT5_PREFIX}")

qt5_add_translation(LUX_QM_FILES
qt/locale/lux_ca.ts
qt/locale/lux_da.ts
qt/locale/lux_de.ts
qt/locale/lux_en.ts
qt/locale/lux_en_US.ts
qt/locale/lux_es.ts
qt/locale/lux_fr_FR.ts
qt/locale/lux_it.ts
qt/locale/lux_ja.ts
qt/locale/lux_pt.ts
qt/locale/lux_ro_RO.ts
qt/locale/lux_ru.ts
qt/locale/lux_zh_TW.ts
)

add_custom_target(locales DEPENDS ${LUX_QM_FILES})
