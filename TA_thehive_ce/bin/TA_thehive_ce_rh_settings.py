
import ta_thehive_ce_declare

from splunktaucclib.rest_handler.endpoint import (
    field,
    validator,
    RestModel,
    MultipleModel,
)
from splunktaucclib.rest_handler import admin_external, util
from splunk_aoblib.rest_migration import ConfigMigrationHandler

util.remove_http_proxy_env_vars()


fields_proxy = [
    field.RestField(
        'proxy_enabled',
        required=False,
        encrypted=False,
        default=None,
        validator=None
    ),
    field.RestField(
        'proxy_type',
        required=False,
        encrypted=False,
        default='http',
        validator=None
    ),
    field.RestField(
        'proxy_url',
        required=False,
        encrypted=False,
        default=None,
        validator=validator.String(
            max_len=4096,
            min_len=0,
        )
    ),
    field.RestField(
        'proxy_port',
        required=False,
        encrypted=False,
        default=None,
        validator=validator.Number(
            max_val=65535,
            min_val=1,
        )
    ),
    field.RestField(
        'proxy_username',
        required=False,
        encrypted=False,
        default=None,
        validator=validator.String(
            max_len=50,
            min_len=0,
        )
    ),
    field.RestField(
        'proxy_password',
        required=False,
        encrypted=True,
        default=None,
        validator=validator.String(
            max_len=8192,
            min_len=0,
        )
    ),
    field.RestField(
        'proxy_rdns',
        required=False,
        encrypted=False,
        default=None,
        validator=None
    )
]
model_proxy = RestModel(fields_proxy, name='proxy')


fields_logging = [
    field.RestField(
        'loglevel',
        required=False,
        encrypted=False,
        default='ERROR',
        validator=None
    )
]
model_logging = RestModel(fields_logging, name='logging')


fields_additional_parameters = [
    field.RestField(
        'thehive_api_key1',
        required=True,
        encrypted=True,
        default='',
        validator=validator.String(
            max_len=32,
            min_len=0,
        )
    ),
    field.RestField(
        'thehive_api_key2',
        required=False,
        encrypted=True,
        default='',
        validator=validator.String(
            max_len=32,
            min_len=0,
        )
    ),
    field.RestField(
        'thehive_api_key3',
        required=False,
        encrypted=True,
        default='',
        validator=validator.String(
            max_len=32,
            min_len=0,
        )
    ),
    field.RestField(
        'thehive_api_key4',
        required=False,
        encrypted=True,
        default='',
        validator=validator.String(
            max_len=32,
            min_len=0,
        )
    ),
    field.RestField(
        'thehive_api_key5',
        required=False,
        encrypted=True,
        default='',
        validator=validator.String(
            max_len=32,
            min_len=0,
        )
    )
]
model_additional_parameters = RestModel(fields_additional_parameters, name='additional_parameters')


endpoint = MultipleModel(
    'ta_thehive_ce_settings',
    models=[
        model_proxy,
        model_logging,
        model_additional_parameters
    ],
)


if __name__ == '__main__':
    admin_external.handle(
        endpoint,
        handler=ConfigMigrationHandler,
    )
