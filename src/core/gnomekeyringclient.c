#include "gnomekeyringclient.h"

#include "common.h"
#include "dklog.h"

#include <security/pam_appl.h>
#include <security/pam_ext.h>
#include <sys/syslog.h>

static int pam_conv_cb(int msg_length, const struct pam_message **msg, struct pam_response **resp, void *app_data)
{
    UNUSED_VALUE(msg_length);
    UNUSED_VALUE(msg);
    UNUSED_VALUE(resp);
    UNUSED_VALUE(app_data);
    return PAM_SUCCESS;
}

bool gnome_keyring_change_pw_by_pam(const char *username, char *currentKey, char *newKey)
{
    int pamRet = PAM_SERVICE_ERR;
    pam_handle_t *phDeepin = NULL;
    do {
        if (currentKey == NULL || newKey == NULL) {
            break;
        }
        char *pw[2] = { currentKey, newKey };
        struct pam_conv conversation = { pam_conv_cb, pw };
        pamRet = pam_start("deepin-keyring-whitebox-password", username, &conversation, &phDeepin);
        if (pamRet != PAM_SUCCESS) {
            break;
        }
        pamRet = pam_chauthtok(phDeepin, 0);
        if (pamRet != PAM_SUCCESS) {
            pam_syslog(phDeepin, LOG_ERR, "[gnome_keyring_change_pw_by_pam] changePW error");
            break;
        }
    } while (0);

    if (phDeepin != NULL) {
        pam_end(phDeepin, pamRet);
    }

    if (pamRet != PAM_SUCCESS) {
        return false;
    }
    return true;
}
