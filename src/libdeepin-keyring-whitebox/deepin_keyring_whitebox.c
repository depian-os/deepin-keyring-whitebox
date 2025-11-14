#include "deepin_keyring_whitebox.h"

#include "dkbackendclient.h"
#include "dkconfig.h"
#include "dkfile.h"

bool deepin_keyring_client_start_deepin_keyring_whitebox(const struct passwd *pwd, const char *password, char *const argument[], char *const *envList)
{
    return dk_client_start_deepin_keyring_whitebox(pwd, password, argument, envList);
}

bool deepin_keyring_file_get_workdir(const char *userHome, char **workDir)
{
    return dk_file_get_workdir(userHome, workDir);
}

bool deepin_keyring_config_enable(const char *workDir)
{
    return dk_config_enable(workDir);
}

bool deepin_keyring_config_is_wb_data(const char *workDir)
{
    return dk_config_is_wb_data(workDir);
}
