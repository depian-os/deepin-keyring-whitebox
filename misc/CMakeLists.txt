
configure_file(pkgconfig/libdeepin-keyring-whitebox.pc.in libdeepin-keyring-whitebox.pc @ONLY)
set(PKGCONFIG
    ${CMAKE_BINARY_DIR}/misc/libdeepin-keyring-whitebox.pc
)
install(FILES ${PKGCONFIG} DESTINATION lib/${CMAKE_LIBRARY_ARCHITECTURE}/pkgconfig)

set(AUTOSTART
    autostart/deepin-keyring-whitebox-notify.desktop
)
install(FILES ${AUTOSTART} DESTINATION /etc/xdg/autostart/)

set(PAM_D
    pam.d/deepin-keyring-whitebox-password
)
install(FILES ${PAM_D} DESTINATION /etc/pam.d/)

set(DCONFIG
    "dsg-configs/org.deepin.dde.keyring.whitebox.json"
)
install(FILES ${DCONFIG} DESTINATION share/dsg/configs/org.deepin.dde.keyring/)
