# coding: utf8

from __future__ import unicode_literals
import ckan.authz as authz
from ckan.common import _

from ckan.lib.base import render_jinja2
from ckan.lib.mailer import mail_recipient
from ckan.lib.mailer import MailerException
import ckan.logic
from ckan.logic.action.create import user_create
from ckan.logic.action.get import package_search
from ckan.logic.action.get import package_show
from ckan.logic.action.get import resource_search
from ckan.logic.action.get import resource_view_list
from ckan.logic import side_effect_free
from ckanext.restricted import auth
from ckanext.restricted import logic
import json
import traceback

try:
    # CKAN 2.7 and later
    from ckan.common import config
except ImportError:
    # CKAN 2.6 and earlier
    from pylons import config

from logging import getLogger
logger = getLogger(__name__)


_get_or_bust = ckan.logic.get_or_bust

NotFound = ckan.logic.NotFound

# Setup logging
import logging
import os
screen_fmt = logging.Formatter(
    '%(asctime)s:%(levelname)s:%(module)s(%(lineno)d) - %(message)s'
)
base_dir = os.path.dirname(os.path.realpath(__file__))
log_file = os.path.join(base_dir, 'restricted_action.log')
fh = logging.FileHandler(log_file)
fh.setFormatter(screen_fmt)
logger.addHandler(fh)
logger.setLevel(logging.INFO)
logger.info('Log file: %s' % log_file)


def restricted_user_create_and_notify(context, data_dict):

    def body_from_user_dict(user_dict):
        body = ''
        for key, value in user_dict.items():
            body += '* {0}: {1}\n'.format(
                key.upper(), value if isinstance(value, str) else str(value))
        return body

    user_dict = user_create(context, data_dict)

    # Send your email, check ckan.lib.mailer for params
    try:
        name = _('CKAN System Administrator')
        email = config.get('email_to')
        if not email:
            raise MailerException('Missing "email-to" in config')

        subject = _('New Registration: {0} ({1})').format(
            user_dict.get('name', _(u'new user')), user_dict.get('email'))

        extra_vars = {
            'site_title': config.get('ckan.site_title'),
            'site_url': config.get('ckan.site_url'),
            'user_info': body_from_user_dict(user_dict)}

        body = render_jinja2(
            'restricted/emails/restricted_user_registered.txt', extra_vars)

        mail_recipient(name, email, subject, body)

    except MailerException as mailer_exception:
        logger.error('Cannot send mail after registration')
        logger.error(mailer_exception)

    return (user_dict)


@side_effect_free
def restricted_resource_view_list(context, data_dict):
    model = context['model']
    id = _get_or_bust(data_dict, 'id')
    resource = model.Resource.get(id)
    if not resource:
        raise NotFound
    authorized = auth.restricted_resource_show(
        context, {'id': resource.get('id'), 'resource': resource}).get('success', False)
    if not authorized:
        return []
    else:
        return resource_view_list(context, data_dict)


@side_effect_free
def restricted_package_show(context, data_dict):

    logger.debug('NOW IN restricted_package_show: %s' % data_dict)
    try:
        package_metadata = package_show(context, data_dict)

        # Ensure user who can edit can see the resource
        if authz.is_authorized(
                'package_update', context, package_metadata).get('success', False):
            return package_metadata

        # Custom authorization
        if isinstance(package_metadata, dict):
            restricted_package_metadata = dict(package_metadata)
        else:
            restricted_package_metadata = dict(package_metadata.for_json())

        # restricted_package_metadata['resources'] = _restricted_resource_list_url(
        #     context, restricted_package_metadata.get('resources', []))
        restricted_package_metadata['resources'] = _restricted_resource_list_hide_fields(
            context, restricted_package_metadata.get('resources', []))

        return (restricted_package_metadata)

    except:
        logger.error('Error in restricted_package_show')
        logger.error(traceback.format_exc())
        # log.warning(u'context: %s' % context)
        logger.warning(type(context))
        logger.warning(u'data_dict: %s' % data_dict)
        pass


@side_effect_free
def restricted_resource_search(context, data_dict):
    resource_search_result = resource_search(context, data_dict)

    restricted_resource_search_result = {}

    for key, value in resource_search_result.items():
        if key == 'results':
            # restricted_resource_search_result[key] = \
            #     _restricted_resource_list_url(context, value)
            restricted_resource_search_result[key] = \
                _restricted_resource_list_hide_fields(context, value)
        else:
            restricted_resource_search_result[key] = value

    return restricted_resource_search_result


@side_effect_free
def restricted_package_search(context, data_dict):
    package_search_result = package_search(context, data_dict)

    restricted_package_search_result = {}

    logger.debug('restricted_package_search, context:')
    for k, v in context.items():
        try:
            logger.debug(u'%s, %s' % (k, v))
        except:
            import traceback
            logger.error(traceback.format_exc())

    for key, value in package_search_result.items():
        if key == 'results':
            restricted_package_search_result_list = []
            for package in value:
                restricted_package_search_result_list.append(
                    restricted_package_show(context, {'id': package.get('id')}))
            restricted_package_search_result[key] = \
                restricted_package_search_result_list
        else:
            restricted_package_search_result[key] = value

    return restricted_package_search_result

# def _restricted_resource_list_url(context, resource_list):
#     restricted_resources_list = []
#     for resource in resource_list:
#         authorized = auth.restricted_resource_show(
#             context, {'id': resource.get('id'), 'resource': resource}).get('success', False)
#         restricted_resource = dict(resource)
#         if not authorized:
#             restricted_resource['url'] = _('Not Authorized')
#         restricted_resources_list += [restricted_resource]
#     return restricted_resources_list

def _restricted_resource_list_hide_fields(context, resource_list):
    restricted_resources_list = []
    for resource in resource_list:
        # copy original resource
        restricted_resource = dict(resource)

        # get the restricted fields
        restricted_dict = logic.restricted_get_restricted_dict(restricted_resource)

        # hide fields to unauthorized users
        authorized = auth.restricted_resource_show(
            context, {'id': resource.get('id'), 'resource': resource}
            ).get('success', False)

        # TODO: hide sensitive resource fields if not authorized
        if not authorized:
            logger.warning('Not authorized for resource: %s' % resource.get('title'))
            logger.info('Resource base fields: %s' % restricted_resource.keys())
            extras = restricted_resource.get('extras')
            if type(extras) is dict:
                logger.info('Resource extras: %s' % extras.keys())
            else:
                logger.warning('No extras')

            # Hide list of sensitive fields
            sensitive = ['locale', 'attribute', 'layer_description', 'change_description_resource',
                         'map_preview_link', 'layer_name', 'disclaimer_url', 'filepath', 'spatial',
                         'attr_data', 'description', 'bbox', 'spatial_type', 'projection_wkt', 'url']
            for s in sensitive:
                if s in restricted_resource:
                    restricted_resource[s] = ''

        # hide other fields in restricted to everyone but dataset owner(s)
        if not authz.is_authorized(
                'package_update', context, {'id': resource.get('package_id')}
                ).get('success'):

            user_name = logic.restricted_get_username_from_context(context)

            # hide partially other allowed user_names (keep own)
            allowed_users = []
            for user in restricted_dict.get('allowed_users'):
                if len(user.strip()) > 0:
                    if user_name == user:
                        allowed_users.append(user_name)
                    else:
                        allowed_users.append(user[0:3] + '*****' + user[-2:])

            new_restricted = json.dumps({
                'level': restricted_dict.get("level"),
                'allowed_users': ','.join(allowed_users)})

            # Resource extras may be stored in an 'extras' subdict, or at the root
            # level of the resource dict.  This block handles both cases.
            extras_restricted = resource.get('extras', {}).get('restricted', {})
            if (extras_restricted):
                restricted_resource['extras']['restricted'] = new_restricted

            field_restricted_field = resource.get('restricted', {})
            if (field_restricted_field):
                restricted_resource['restricted'] = new_restricted

        restricted_resources_list += [restricted_resource]
    return restricted_resources_list
