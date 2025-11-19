"""Enums.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from enum import UNIQUE, IntEnum, StrEnum, verify


class AceType(IntEnum):
    """ACE types."""

    CREATE_CHILD = 1
    READ = 2
    WRITE = 3
    DELETE = 4
    PASSWORD_MODIFY = 5


class RoleScope(IntEnum):
    """Scope of the role."""

    BASE_OBJECT = 0
    SINGLE_LEVEL = 1
    WHOLE_SUBTREE = 2


class MFAFlags(IntEnum):
    """Two-Factor auth action."""

    DISABLED = 0
    ENABLED = 1
    WHITELIST = 2


class MFAChallengeStatuses(StrEnum):
    """Two-Factor challenge status."""

    BYPASS = "bypass"
    PENDING = "pending"


class KindType(StrEnum):
    """Object kind types."""

    STRUCTURAL = "STRUCTURAL"
    ABSTRACT = "ABSTRACT"
    AUXILIARY = "AUXILIARY"


class AuditSeverity(IntEnum):
    """Audit policy severity."""

    EMERGENCY = 0
    ALERT = 1
    CRITICAL = 2
    ERROR = 3
    WARNING = 4
    NOTICE = 5
    INFO = 6
    DEBUG = 7


class AuditDestinationProtocolType(StrEnum):
    """Audit destination protocol type."""

    UDP = "udp"
    TCP = "tcp"


class AuditDestinationServiceType(StrEnum):
    """Audit destination type."""

    SYSLOG = "syslog"


@verify(UNIQUE)
class AuthoruzationRules(IntEnum):
    """API Permissions."""

    PASSWORD_POLICY_GET_ALL = 1
    PASSWORD_POLICY_GET = 2
    PASSWORD_POLICY_GET_BY_DIR = 3
    PASSWORD_POLICY_UPDATE = 4
    PASSWORD_POLICY_RESET_DOMAIN_POLICY = 5
    PASSWORD_POLICY_TURNOFF = 6
    NETWORK_POLICY_CREATE = 7
    NETWORK_POLICY_GET_LIST_POLICIES = 8
    NETWORK_POLICY_DELETE = 9
    NETWORK_POLICY_SWITCH_NETWORK_POLICY = 10
    NETWORK_POLICY_SWAP_PRIORITIES = 11
    NETWORK_POLICY_UPDATE = 12
    DHCP_CHANGE_STATE = 13
    DHCP_GET_STATE = 14
    DHCP_CREATE_SUBNET = 15
    DHCP_DELETE_SUBNET = 16
    DHCP_GET_SUBNETS = 17
    DHCP_UPDATE_SUBNET = 18
    DHCP_CREATE_LEASE = 19
    DHCP_RELEASE_LEASE = 20
    DHCP_LIST_ACTIVE_LEASES = 21
    DHCP_FIND_LEASE = 22
    DHCP_LEASE_TO_RESERVATION = 23
    DHCP_ADD_RESERVATION = 24
    DHCP_GET_RESERVATIONS = 25
    DHCP_UPDATE_RESERVATION = 26
    DHCP_DELETE_RESERVATION = 27
    ATTRIBUTE_TYPE_GET = 28
    ATTRIBUTE_TYPE_CREATE = 29
    ATTRIBUTE_TYPE_GET_PAGINATOR = 30
    ATTRIBUTE_TYPE_UPDATE = 31
    ATTRIBUTE_TYPE_DELETE_ALL_BY_NAMES = 32
    ENTITY_TYPE_GET = 33
    ENTITY_TYPE_CREATE = 34
    ENTITY_TYPE_GET_PAGINATOR = 35
    ENTITY_TYPE_UPDATE = 36
    ENTITY_TYPE_DELETE_ALL_BY_NAMES = 37
    ENTITY_TYPE_GET_ATTRIBUTES = 38
    OBJECT_CLASS_GET = 39
    OBJECT_CLASS_CREATE = 40
    OBJECT_CLASS_GET_PAGINATOR = 41
    OBJECT_CLASS_UPDATE = 42
    OBJECT_CLASS_DELETE_ALL_BY_NAMES = 43
    DNS_SETUP_DNS = 44
    DNS_CREATE_RECORD = 45
    DNS_DELETE_RECORD = 46
    DNS_UPDATE_RECORD = 47
    DNS_GET_ALL_RECORDS = 48
    DNS_GET_DNS_STATUS = 49
    DNS_GET_ALL_ZONES_RECORDS = 50
    DNS_GET_FORWARD_ZONES = 51
    DNS_CREATE_ZONE = 52
    DNS_UPDATE_ZONE = 53
    DNS_DELETE_ZONE = 54
    DNS_CHECK_DNS_FORWARD_ZONE = 55
    DNS_RELOAD_ZONE = 56
    DNS_UPDATE_SERVER_OPTIONS = 57
    DNS_GET_SERVER_OPTIONS = 58
    DNS_RESTART_SERVER = 59
    KRB_SETUP_CATALOGUE = 60
    KRB_SETUP_KDC = 61
    KRB_KTADD = 62
    KRB_GET_STATUS = 63
    KRB_ADD_PRINCIPAL = 64
    KRB_RENAME_PRINCIPAL = 65
    KRB_RESET_PRINCIPAL_PW = 66
    KRB_DELETE_PRINCIPAL = 67
    AUDIT_GET_POLICIES = 68
    AUDIT_UPDATE_POLICY = 69
    AUDIT_GET_DESTINATIONS = 70
    AUDIT_CREATE_DESTINATION = 71
    AUDIT_DELETE_DESTINATION = 72
    AUDIT_UPDATE_DESTINATION = 73
    AUTH_RESET_PASSWORD = 74
    MFA_SETUP = 75
    MFA_REMOVE = 76
    MFA_GET = 77
    SESSION_GET_USER_SESSIONS = 78
    SESSION_CLEAR_USER_SESSIONS = 79
    SESSION_DELETE = 80

    __descriptions__ = {
        PASSWORD_POLICY_GET_ALL: "Получение всех политик паролей",
        PASSWORD_POLICY_GET: "Получение конкретной политики",
        PASSWORD_POLICY_GET_BY_DIR: "Получение конкретной политики по пути директории",  # noqa: E501
        PASSWORD_POLICY_UPDATE: "Обновление парольной политики",
        PASSWORD_POLICY_RESET_DOMAIN_POLICY: "Сброс парольной политики к настройкам по умолчанию",  # noqa: E501
        PASSWORD_POLICY_TURNOFF: "Выключение парольной политики",
        NETWORK_POLICY_CREATE: "Создание сетевой политики",
        NETWORK_POLICY_GET_LIST_POLICIES: "Получение списка сетевых политик",
        NETWORK_POLICY_DELETE: "Удаление сетевой политики",
        NETWORK_POLICY_SWITCH_NETWORK_POLICY: "Переключение активной сетевой политики",  # noqa: E501
        NETWORK_POLICY_SWAP_PRIORITIES: "Обмен приоритетами сетевых политик",
        NETWORK_POLICY_UPDATE: "Обновление параметров сетевой политики",
        DHCP_CHANGE_STATE: "Изменение состояния DHCP-сервиса",
        DHCP_GET_STATE: "Получение текущего состояния DHCP-сервиса",
        DHCP_CREATE_SUBNET: "Создание подсети DHCP",
        DHCP_DELETE_SUBNET: "Удаление подсети DHCP",
        DHCP_GET_SUBNETS: "Получение списка подсетей DHCP",
        DHCP_UPDATE_SUBNET: "Обновление подсети DHCP",
        DHCP_CREATE_LEASE: "Создание аренды DHCP",
        DHCP_RELEASE_LEASE: "Освобождение аренды DHCP",
        DHCP_LIST_ACTIVE_LEASES: "Получение списка активных арен DHCP",
        DHCP_FIND_LEASE: "Поиск аренды DHCP",
        DHCP_LEASE_TO_RESERVATION: "Преобразование аренды в резервацию DHCP",
        DHCP_GET_RESERVATIONS: "Получение списка DHCP-резерваций",
        DHCP_UPDATE_RESERVATION: "Обновление DHCP-резервации",
        DHCP_DELETE_RESERVATION: "Удаление DHCP-резервации",
        DHCP_ADD_RESERVATION: "Добавление DHCP-резервации",
        ATTRIBUTE_TYPE_GET: "Получение типа атрибута",
        ATTRIBUTE_TYPE_CREATE: "Создание типа атрибута",
        ATTRIBUTE_TYPE_GET_PAGINATOR: "Постраничное получение типов атрибутов",
        ATTRIBUTE_TYPE_UPDATE: "Обновление типа атрибута",
        ATTRIBUTE_TYPE_DELETE_ALL_BY_NAMES: "Удаление типов атрибутов по именам",  # noqa: E501
        ENTITY_TYPE_GET: "Получение типа сущности",
        ENTITY_TYPE_CREATE: "Создание типа сущности",
        ENTITY_TYPE_GET_PAGINATOR: "Постраничное получение типов сущностей",
        ENTITY_TYPE_UPDATE: "Обновление типа сущности",
        ENTITY_TYPE_DELETE_ALL_BY_NAMES: "Удаление типов сущностей по именам",
        ENTITY_TYPE_GET_ATTRIBUTES: "Получение атрибутов типа сущности",
        OBJECT_CLASS_GET: "Получение объектного класса",
        OBJECT_CLASS_CREATE: "Создание объектного класса",
        OBJECT_CLASS_GET_PAGINATOR: "Постраничное получение объектных классов",
        OBJECT_CLASS_UPDATE: "Обновление объектного класса",
        OBJECT_CLASS_DELETE_ALL_BY_NAMES: "Удаление объектных классов по именам",  # noqa: E501
        DNS_SETUP_DNS: "Первичная настройка DNS-сервера",
        DNS_CREATE_RECORD: "Создание DNS-записи",
        DNS_DELETE_RECORD: "Удаление DNS-записи",
        DNS_UPDATE_RECORD: "Обновление DNS-записи",
        DNS_GET_ALL_RECORDS: "Получение всех DNS-записей",
        DNS_GET_DNS_STATUS: "Получение статуса DNS-сервера",
        DNS_GET_ALL_ZONES_RECORDS: "Получение записей всех DNS-зон",
        DNS_GET_FORWARD_ZONES: "Получение списка прямых DNS-зон",
        DNS_CREATE_ZONE: "Создание DNS-зоны",
        DNS_UPDATE_ZONE: "Обновление DNS-зоны",
        DNS_DELETE_ZONE: "Удаление DNS-зоны",
        DNS_CHECK_DNS_FORWARD_ZONE: "Проверка DNS-прямой зоны",
        DNS_RELOAD_ZONE: "Перезагрузка DNS-зоны",
        DNS_UPDATE_SERVER_OPTIONS: "Обновление настроек DNS-сервера",
        DNS_GET_SERVER_OPTIONS: "Получение настроек DNS-сервера",
        DNS_RESTART_SERVER: "Перезапуск DNS-сервера",
        KRB_SETUP_CATALOGUE: "Настройка каталога Kerberos",
        KRB_SETUP_KDC: "Настройка центра распределения ключей",
        KRB_KTADD: "Добавление ключа в keytab",
        KRB_GET_STATUS: "Получение статуса Kerberos",
        KRB_ADD_PRINCIPAL: "Создание Kerberos-принципала",
        KRB_RENAME_PRINCIPAL: "Переименование Kerberos-принципала",
        KRB_RESET_PRINCIPAL_PW: "Сброс пароля Kerberos-принципала",
        KRB_DELETE_PRINCIPAL: "Удаление Kerberos-принципала",
        AUDIT_GET_POLICIES: "Получение политик аудита",
        AUDIT_UPDATE_POLICY: "Обновление политики аудита",
        AUDIT_GET_DESTINATIONS: "Получение направлений аудита",
        AUDIT_CREATE_DESTINATION: "Создание направления аудита",
        AUDIT_DELETE_DESTINATION: "Удаление направления аудита",
        AUDIT_UPDATE_DESTINATION: "Обновление направления аудита",
        AUTH_RESET_PASSWORD: "Сброс пароля пользователя",
        MFA_SETUP: "Настройка MFA для пользователя",
        MFA_REMOVE: "Удаление MFA у пользователя",
        MFA_GET: "Получение настроек MFA",
        SESSION_GET_USER_SESSIONS: "Получение пользовательских сессий",
        SESSION_CLEAR_USER_SESSIONS: "Очистка пользовательских сессий",
        SESSION_DELETE: "Удаление пользовательской сессии",
    }

    @property
    def description(self) -> str:
        return self.__descriptions__.get(self, "")
