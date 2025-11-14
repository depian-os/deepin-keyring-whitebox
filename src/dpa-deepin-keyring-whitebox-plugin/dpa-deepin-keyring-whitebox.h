#pragma once

#include <dpa/agent-extension-proxy.h>
#include <dpa/agent-extension.h>

#include <QButtonGroup>
#include <QCheckBox>
#include <QObject>

class GnomeKeyringExtention : public QObject, dpa::AgentExtension
{
    Q_OBJECT
    Q_INTERFACES(dpa::AgentExtension)
    Q_PLUGIN_METADATA(IID AgentExtensionPluginIID FILE "dpa-deepin-keyring-whitebox.json")
public:
    explicit GnomeKeyringExtention(QObject *parent = 0);

    void initialize(dpa::AgentExtensionProxy *proxy) Q_DECL_OVERRIDE;
    void finalize() Q_DECL_OVERRIDE;

    QStringList interestedActions() const Q_DECL_OVERRIDE;
    QString description() const Q_DECL_OVERRIDE;

    QButtonGroup *options() Q_DECL_OVERRIDE;

    void extendedDo() Q_DECL_OVERRIDE;

private:
    dpa::AgentExtensionProxy *m_proxy;

    QPointer<QCheckBox> m_checkBtn;

    void useWhiteboxPassword(const QString &password);
    void useUserPassword(const QString &password);
};
