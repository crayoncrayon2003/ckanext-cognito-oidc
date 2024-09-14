import pytest

import ckan.plugins as p


@pytest.mark.ckan_config("ckan.plugins", "cognito_oidc")
@pytest.mark.usefixtures("with_plugins")
def test_plugin():
    assert plugin_loaded("cognito_oidc")
