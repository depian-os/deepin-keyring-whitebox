// SPDX-FileCopyrightText: 2017 - 2023 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

#include "dpa-deepin-keyring-whitebox.h"

#include "dkbackendclient.h"
#include "dkconfig.h"
#include "dkfile.h"

#include <QCheckBox>
#include <QDBusInterface>
#include <QDebug>

#include <unistd.h>

static const QString ActionEnableAutoLogin = "org.deepin.dde.accounts.enable-auto-login";
static const QString ActionDisableAutoLogin = "org.deepin.dde.accounts.disable-auto-login";
static const QString ActionEnableNopassLogin = "org.deepin.dde.accounts.enable-nopass-login";
static const QString ActionDisableNopassLogin = "org.deepin.dde.accounts.disable-nopass-login";
static const QString ActionEnrollFingerprint = "org.deepin.dde.authenticate.fingerprint.enroll";
static const QString ActionEnrollFace = "org.deepin.dde.authenticate.face.enroll";
static const QString ActionEnrollIris = "org.deepin.dde.authenticate.iris.enroll";
static const QString ActionPasskeyRegister = "com.deepin.dde.passkey.dcc-plugin.register";
static const QString ActionEnableQuickLogin = "org.deepin.dde.accounts.enable-quick-login";
static const QString ActionDisableQuickLogin = "org.deepin.dde.accounts.disable-quick-login";
static const QString ActionEnableWechatAuth = "org.deepin.dde.accounts.enable-wechat-auth";
static const QString ActionDisableWechatAuth = "org.deepin.dde.accounts.disable-wechat-auth";
static const QString ActionDoAuthorized = "org.deepin.dde.Authority1.doAuthorized";

GnomeKeyringExtention::GnomeKeyringExtention(QObject *parent)
    : QObject(parent)
    , m_proxy(nullptr)
    , m_checkBtn(nullptr)
{
}

void GnomeKeyringExtention::initialize(dpa::AgentExtensionProxy *proxy)
{
    m_proxy = proxy;
}

void GnomeKeyringExtention::finalize() { }

QStringList GnomeKeyringExtention::interestedActions() const
{
    QStringList ret;
    ret << ActionEnableAutoLogin
        << ActionDisableAutoLogin
        << ActionEnableNopassLogin
        << ActionDisableNopassLogin
        << ActionEnrollFingerprint
        << ActionEnrollFace
        << ActionEnrollIris
        << ActionPasskeyRegister
        << ActionEnableQuickLogin
        << ActionDisableQuickLogin
        << ActionEnableWechatAuth
        << ActionDisableWechatAuth;

    return ret;
}

QString GnomeKeyringExtention::description() const
{
    return "";
}

QButtonGroup *GnomeKeyringExtention::options()
{
    const QString actionID = m_proxy->actionID();

    if (m_checkBtn.isNull()) {
        m_checkBtn = new QCheckBox;
    }
    m_checkBtn->setChecked(true);

    if (actionID == ActionEnableAutoLogin
        || actionID == ActionEnableNopassLogin
        || actionID == ActionEnrollFingerprint
        || actionID == ActionEnrollFace
        || actionID == ActionEnrollIris
        || actionID == ActionPasskeyRegister
        || actionID == ActionEnableQuickLogin
        || actionID == ActionEnableWechatAuth) {
        m_checkBtn.data()->setText("use whitebox keyring"); // 现在不需要交互, 文案随便填的
    } else if (actionID == ActionDisableAutoLogin || actionID == ActionDisableNopassLogin || actionID == ActionDisableWechatAuth) {
        m_checkBtn.data()->setText("do not use whitebox keyring");
    }

    // bug11577场景：同时打开自动登录和免密登录，再关闭其中一个，此时鉴权窗口中勾选了恢复密钥环
    // 修复方案：自动登录和免密登录时，密钥环操作不作勾选
    // 暂时没有还原要求，这里省掉dbus操作
    // QDBusInterface *inter =
    //         new QDBusInterface("com.deepin.daemon.Accounts", "/com/deepin/daemon/Accounts/User" + QString::number(getuid()), "com.deepin.daemon.Accounts.User", QDBusConnection::systemBus());
    // bool npLogin = inter->property("NoPasswdLogin").toBool();
    // bool amLogin = inter->property("AutomaticLogin").toBool();
    // inter->deleteLater();
    // m_checkBtn.data()->setChecked(!(npLogin && amLogin));

    QButtonGroup *group = new QButtonGroup;
    // 现在不需要交互，后续会增加交互
    // group->addButton(m_checkBtn);
    group->setExclusive(false);

    return group;
}

void GnomeKeyringExtention::extendedDo()
{
    qDebug() << "GnomeKeyringExtention extendedDo";
    const QString actionID = m_proxy->actionID();
    const QString password = m_proxy->password();

    if (actionID == ActionEnableAutoLogin
        || actionID == ActionEnableNopassLogin
        || actionID == ActionEnrollFingerprint
        || actionID == ActionEnrollFace
        || actionID == ActionEnrollIris
        || actionID == ActionPasskeyRegister
        || actionID == ActionEnableQuickLogin
        || actionID == ActionEnableWechatAuth) {
        if (!m_checkBtn.isNull() && m_checkBtn.data()->checkState() == Qt::Checked) {
            useWhiteboxPassword(password);
        }
    } else if (actionID == ActionDisableAutoLogin || actionID == ActionDisableNopassLogin || actionID == ActionDisableWechatAuth) {
        if (!m_checkBtn.isNull() && m_checkBtn.data()->checkState() == Qt::Checked) {
            useUserPassword(password);
        }
    }
}

void GnomeKeyringExtention::useWhiteboxPassword(const QString &password)
{
    qDebug() << "use whitebox password";
    char *workDir = nullptr;
    do {
        struct passwd *pwd = getpwuid(getuid());
        if (pwd == nullptr) {
            break;
        }
        if (!dk_file_get_workdir(pwd->pw_dir, &workDir)) {
            break;
        }
        if (!dk_config_is_wb_data(workDir)) {
            dk_client_start_deepin_keyring_whitebox(pwd, password.toStdString().c_str(), dk_client_start_args_of_dpa_to_wb(), nullptr);
        }
    } while (false);
    if (workDir != nullptr) {
        free(workDir);
    }
}

void GnomeKeyringExtention::useUserPassword(const QString &password)
{
    Q_UNUSED(password);
    qDebug() << "use user password";
    // 现在不需要做还原
}
