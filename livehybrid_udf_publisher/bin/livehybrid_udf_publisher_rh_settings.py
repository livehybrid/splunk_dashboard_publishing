
import livehybrid_udf_publisher_declare
import logging as logger
from splunktaucclib.rest_handler.endpoint import (
    field,
    validator,
    RestModel,
    MultipleModel,
)
import os
from splunktaucclib.rest_handler import admin_external, util
from splunk_aoblib.rest_migration import ConfigMigrationHandler

util.remove_http_proxy_env_vars()
logger.basicConfig(level=logger.INFO,
                   format='%(asctime)s %(levelname)s %(message)s',
                   filename=os.path.join(os.getenv('SPLUNK_HOME','/opt/splunk'),'var','log','splunk','publisher_settings.log'),
                   filemode='a'
                   )

logger.info("Start")

fields_logging = [
    field.RestField(
        'loglevel',
        required=False,
        encrypted=False,
        default='INFO',
        validator=None
    )
]
model_logging = RestModel(fields_logging, name='logging')

fields_additional_parameters = [
    field.RestField(
        'aws_access_key',
        required=True,
        encrypted=True,
        default='',
        validator=validator.String(
            max_len=8192,
            min_len=0,
        )
    ),
    field.RestField(
        'aws_secret_key',
        required=True,
        encrypted=True,
        default='',
        validator=validator.String(
            max_len=8192,
            min_len=0,
        )
    ),
    field.RestField(
        'iam_role_arn',
        required=False,
        encrypted=True,
        default='',
        validator=validator.String(
            max_len=8192,
            min_len=0,
        )
    )

]
model_additional_parameters = RestModel(fields_additional_parameters, name='additional_parameters')


endpoint = MultipleModel(
    'livehybrid_udf_publisher_settings',
    models=[
        model_logging,
        model_additional_parameters
    ],
)


if __name__ == '__main__':
    admin_external.handle(
        endpoint,
        handler=ConfigMigrationHandler,
    )
logger.debug("End")
