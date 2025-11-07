 
import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress
import re
import time
import argparse
import sys
import json
import select
import ssl
import struct
from datetime import datetime
import logging
import csv
import os

try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False

PROTOCOL_DESCRIPTIONS = {
    'http': "HTTP (HyperText Transfer Protocol) - протокол для передачи веб-страниц. Порт 80 обычно используется для нешифрованного веб-трафика.",
    'https': "HTTPS (HTTP Secure) - защищенная версия HTTP, использует шифрование TLS/SSL. Порт 443 используется для защищенного веб-трафика.",
    'ftp': "FTP (File Transfer Protocol) - протокол для передачи файлов между клиентом и сервером. Порт 21 используется для управления, порт 20 — для передачи данных.",
    'ftps': "FTPS (FTP Secure) - защищенная версия FTP, использует SSL/TLS для шифрования данных. Порт 990 используется для управления.",
    'sftp': "SFTP (SSH File Transfer Protocol) - протокол для передачи файлов через SSH. Обычно использует порт 22.",
    'ssh': "SSH (Secure Shell) - протокол для безопасного удаленного управления системой. Также используется для туннелирования и передачи файлов. Порт 22.",
    'telnet': "Telnet - протокол для удаленного доступа к командной строке. Порт 23. Небезопасен, так как передает данные в открытом виде.",
    'smtp': "SMTP (Simple Mail Transfer Protocol) - протокол для отправки электронной почты. Порт 25.",
    'smtps': "SMTPS - защищенная версия SMTP, использует SSL/TLS. Порт 465 или 587 (с STARTTLS).",
    'imap': "IMAP (Internet Message Access Protocol) - протокол для доступа к электронной почте. Порт 143 (незащищенный), 993 (IMAPS).",
    'pop3': "POP3 (Post Office Protocol) - протокол для получения электронной почты. Порт 110 (незащищенный), 995 (POP3S).",
    'dns': "DNS (Domain Name System) - система преобразования доменных имен в IP-адреса. Порт 53 (UDP/TCP).",
    'mysql': "MySQL - система управления реляционными базами данных. Порт 3306.",
    'postgresql': "PostgreSQL - продвинутая система управления реляционными базами данных. Порт 5432.",
    'mssql': "Microsoft SQL Server - система управления реляционными базами данных от Microsoft. Порт 1433.",
    'mongodb': "MongoDB - документоориентированная система управления базами данных NoSQL. Порт 27017.",
    'redis': "Redis - хранилище структур данных в памяти, используется как база данных, кэш и брокер сообщений. Порт 6379.",
    'oracle': "Oracle Database - система управления реляционными базами данных от Oracle. Порт 1521.",
    'elasticsearch': "Elasticsearch - поисковый и аналитический движок. Порт 9200 (HTTP API), 9300 (внутренняя связь).",
    'rdp': "RDP (Remote Desktop Protocol) - протокол для удаленного рабочего стола. Порт 3389.",
    'vnc': "VNC (Virtual Network Computing) - система удаленного доступа к рабочему столу. Порт 5900 + номер дисплея (например, 5901).",
    'snmp': "SNMP (Simple Network Management Protocol) - протокол для управления сетевыми устройствами. Порт 161 (UDP).",
    'ldap': "LDAP (Lightweight Directory Access Protocol) - протокол для доступа к службам каталогов. Порт 389 (незащищенный), 636 (LDAPS).",
    'dhcp': "DHCP (Dynamic Host Configuration Protocol) - протокол для автоматической выдачи IP-адресов. Порт 67 (сервер), 68 (клиент).",
    'sip': "SIP (Session Initiation Protocol) - протокол для установления сеансов связи, часто используется в VoIP. Порт 5060 (UDP/TCP).",
    'rtsp': "RTSP (Real Time Streaming Protocol) - протокол для управления потоками мультимедиа. Порт 554.",
    'rtp': "RTP (Real-time Transport Protocol) - протокол для передачи аудио и видео в реальном времени. Обычно использует динамические порты.",
    'minecraft': "Minecraft - популярная игра. Порт 25565 (сервер).",
    'amqp': "AMQP (Advanced Message Queuing Protocol) - протокол для обмена сообщениями. Порт 5672 (незащищенный), 5671 (AMQPS).",
    'kafka': "Apache Kafka - распределенная система потоковой передачи данных. Порт 9092.",
    'syslog': "Syslog - протокол для передачи логов. Порт 514 (UDP/TCP).",
    'ipsec': "IPSec (Internet Protocol Security) - набор протоколов для защиты данных на сетевом уровне. Порты 500 (UDP, IKE), 4500 (UDP, NAT-T).",
    'nfs': "NFS (Network File System) - протокол для доступа к файлам по сети. Порт 2049 (TCP/UDP).",
    'smb': "SMB (Server Message Block) - протокол для совместного доступа к файлам и принтерам. Порт 445 (TCP).",
    'ntp': "NTP (Network Time Protocol) - протокол для синхронизации времени. Порт 123 (UDP).",
    'ntp-udp': "NTP (Network Time Protocol) - протокол для синхронизации времени. Порт 123 (UDP).",
    'unknown': "Неизвестный протокол. Может быть кастомной службой или нестандартным протоколом.",
    'unknown-tcp': "Неизвестный TCP-протокол. Служба отвечает на подключение, но не распознана.",
    'unknown-udp': "Неизвестный UDP-протокол. Служба отвечает на UDP-запросы, но не распознана.",
    'http-alt': "HTTP Alternate - часто используется для веб-серверов. Порт 8080.",
    'tomcat': "Apache Tomcat - сервер для Java-приложений. Порт 8080.",
    'proxy': "Proxy - часто используется для прокси-серверов. Порт 3128, 8080.",
    'memcached': "Memcached - система кэширования данных в памяти. Порт 11211.",
    'kafka-broker': "Apache Kafka Broker - порт для связи между брокерами Kafka. Порт 9093 (внутренняя связь).",
    'zookeeper': "Apache ZooKeeper - сервис для управления конфигурацией распределенных систем. Порт 2181.",
    'influxdb': "InfluxDB - база данных для хранения временных рядов. Порт 8086.",
    'grafana': "Grafana - платформа для визуализации данных. Порт 3000.",
    'prometheus': "Prometheus - система мониторинга и оповещения. Порт 9090.",
    'docker-registry': "Docker Registry - хранилище Docker-образов. Порт 5000.",
    'kubernetes-api': "Kubernetes API Server - порт для управления кластером Kubernetes. Порт 6443.",
    'etcd': "etcd - хранилище ключ-значение для распределенных систем. Порт 2379 (клиент), 2380 (внутренняя связь).",
    'consul': "Consul - сервис для обнаружения и конфигурации сервисов. Порт 8500 (HTTP API).",
    'rabbitmq': "RabbitMQ - брокер сообщений. Порт 5672 (AMQP), 15672 (управление).",
    'icmp': "ICMP (Internet Control Message Protocol) - протокол для отправки служебных сообщений и диагностики (ping, traceroute). Не использует порты, работает поверх IP.",
    'bgp': "BGP (Border Gateway Protocol) - протокол динамической маршрутизации в интернете. Порт 179 (TCP).",
    'tftp': "TFTP (Trivial File Transfer Protocol) - упрощенный протокол передачи файлов без аутентификации. Порт 69 (UDP).",
    'rsync': "Rsync - протокол и утилита для эффективной синхронизации файлов. Порт 873.",
    'rpc': "RPC (Remote Procedure Call) - протокол для вызова процедур на удаленной машине. Часто использует порт 111 (portmapper).",
    'nfs-mount': "NFS Mount - служба монтирования сетевых файловых систем NFS. Порт 2048 (TCP/UDP) или динамические.",
    'ipmi': "IPMI (Intelligent Platform Management Interface) - протокол для удаленного управления серверами. Порт 623 (UDP).",
    'ldaps': "LDAPS (LDAP Secure) - защищенная версия LDAP поверх SSL/TLS. Порт 636.",
    'http-proxy': "HTTP Proxy - прокси-сервер для HTTP-трафика. Часто использует порты 3128, 8080, 8081.",
    'soap': "SOAP (Simple Object Access Protocol) - протокол для обмена структурированными сообщениями в веб-сервисах. Обычно поверх HTTP/HTTPS (порты 80, 443).",
    'rest-api': "REST API (Representational State Transfer) - архитектурный стиль для веб-сервисов. Обычно использует HTTP/HTTPS (порты 80, 443).",
    'graphql': "GraphQL - язык запросов и среда выполнения для API. Обычно использует HTTP/HTTPS (порты 80, 443).",
    'grpc': "gRPC (gRPC Remote Procedure Calls) - высокопроизводительный RPC-фреймворк от Google. Обычно порт 50051.",
    'websocket': "WebSocket - протокол для полнодуплексной связи поверх HTTP. Использует порты 80 (ws) или 443 (wss).",
    'cassandra': "Apache Cassandra - распределенная NoSQL база данных. Порт 9042 (клиентские соединения).",
    'couchdb': "Apache CouchDB - документоориентированная NoSQL база данных. Порт 5984 (HTTP), 5986 (HTTPS).",
    'riak': "Riak - распределенная NoSQL база данных. Порт 8087 (Protocol Buffers), 8098 (HTTP).",
    'couchbase': "Couchbase - документоориентированная NoSQL база данных. Порт 8091 (Web UI), 11210 (Data).",
    'rethinkdb': "RethinkDB - база данных для реального времени. Порт 8080 (Web UI), 28015 (драйверы).",
    'clickhouse': "ClickHouse - колоночная СУБД для аналитики. Порт 8123 (HTTP), 9000 (клиент-сервер).",
    'snowflake': "Snowflake - облачная data warehouse. Порт 443 (HTTPS).",
    'kubernetes-nodeport': "Kubernetes NodePort - сервис, открывающий порт на всех узлах кластера. Обычно в диапазоне 30000-32767.",
    'istio-pilot': "Istio Pilot - компонент сервисной сетки Istio для управления конфигурацией. Порт 15010, 15011.",
    'linkerd': "Linkerd - сервисная сетка (service mesh). Порт 4143 (входящий трафик), 4191 (дашборд).",
    'helm': "Helm - менеджер пакетов для Kubernetes. Порт 44134 (Tiller, в устаревших версиях).",
    'nats': "NATS - высокопроизводительная система обмена сообщениями. Порт 4222 (клиенты), 8222 (мониторинг).",
    'rabbitmq-management': "RabbitMQ Management - веб-интерфейс для управления RabbitMQ. Порт 15672.",
    'activemq': "Apache ActiveMQ - брокер сообщений. Порт 61616 (OpenWire), 8161 (Web UI).",
    'zeromq': "ZeroMQ - библиотека для работы с сообщениями без брокера. Использует различные транспортные механизмы.",
    'nagios': "Nagios - система мониторинга. Порт 5666 (NRPE).",
    'zabbix': "Zabbix - система мониторинга. Порт 10051 (сервер).",
    'pagerduty': "PagerDuty - платформа для управления инцидентами. Интегрируется через API (порт 443).",
    'datadog': "Datadog - платформа мониторинга и аналитики. Использует API (порт 443).",
    'newrelic': "New Relic - платформа для мониторинга приложений. Использует API (порт 443).",
    'puppet': "Puppet - система управления конфигурациями. Порт 8140.",
    'chef': "Chef - система управления конфигурациями. Порт 443 (HTTPS).",
    'ansible': "Ansible - система управления конфигурациями и оркестрации. Обычно использует SSH (порт 22).",
    'saltstack': "SaltStack - система управления конфигурациями. Порт 4505 (Publisher), 4506 (Request Server).",
    'teamspeak': "TeamSpeak - система голосовой связи. Порт 10011 (ServerQuery), 9987 (голосовой, UDP).",
    'discord': "Discord - платформа для общения. Использует различные порты и протоколы (в основном HTTPS и WebRTC).",
    'ventrilo': "Ventrilo - система голосовой связи. Порт 3784 (сервер).",
    'xmpp': "XMPP (Extensible Messaging and Presence Protocol) - протокол для обмена сообщениями. Порт 5222 (клиент-сервер), 5269 (сервер-сервер).",
    'tls': "TLS (Transport Layer Security) - протокол для обеспечения безопасной связи. Используется поверх TCP (часто порт 443).",
    'ssl': "SSL (Secure Sockets Layer) - устаревший предшественник TLS. Термин часто используется для обозначения TLS.",
    'kerberos': "Kerberos - сетевой протокол аутентификации. Порт 88 (TCP/UDP).",
    'h323': "H.323 - протокол для мультимедийной связи (VoIP, видеоконференции). Использует порт 1720 (H.225).",
    'iscsi': "iSCSI (Internet Small Computer Systems Interface) - протокол для передачи данных хранилищ. Порт 3260.",
    'bacnet': "BACnet - протокол для автоматизации зданий. Порт 47808 (UDP).",
    'modbus': "Modbus - протокол промышленной сети. Порт 502 (TCP).",
    'steam': "Steam - игровая платформа. Использует множество портов, включая 27015 (игровые серверы).",
    'counterstrike': "Counter-Strike - игровой сервер. Порт 27015.",
    'teamspeak3': "TeamSpeak 3 - сервер голосовой связи для геймеров. Порт 9987 (UDP, голос), 10011 (TCP, ServerQuery), 30033 (TCP, File transfer).",
    'minecraft-pe': "Minecraft: Pocket Edition - сервер для мобильной версии. Порт 19132 (UDP).",
    'irc': "IRC (Internet Relay Chat) - протокол для группового обмена сообщениями. Порт 6667.",
    'nntp': "NNTP (Network News Transfer Protocol) - протокол для чтения и отправки новостных групп. Порт 119.",
    'whois': "WHOIS - протокол для получения информации о доменах и IP-адресах. Порт 43.",
    'kerberos-adm': "Kerberos Administration - служба управления Kerberos. Порт 749.",
    'kpasswd': "Kerberos Password Change - служба смены пароля Kerberos. Порт 464.",
    'afp': "AFP (Apple Filing Protocol) - протокол для совместного доступа к файлам в сетях Apple. Порт 548.",
    'apple-airplay': "Apple AirPlay - протокол для беспроводной потоковой передачи медиа. Порт 7000.",
    'apple-facetime': "Apple FaceTime - сервис видеозвонков. Использует различные порты и протоколы.",
    'netbios-ns': "NetBIOS Name Service - служба разрешения имен в сетях Windows. Порт 137 (UDP).",
    'netbios-dgm': "NetBIOS Datagram Service - служба датаграмм в сетях Windows. Порт 138 (UDP).",
    'netbios-ssn': "NetBIOS Session Service - служба сессий в сетях Windows. Порт 139 (TCP).",
    'llmnr': "LLMNR (Link-Local Multicast Name Resolution) - протокол разрешения имен в локальной сети. Порт 5355 (UDP).",
    'mdns': "mDNS (Multicast DNS) - протокол разрешения имен через multicast. Порт 5353 (UDP).",
    'upnp': "UPnP (Universal Plug and Play) - протокол для автоматического обнаружения сетевых устройств. Порт 1900 (UDP).",
    'ssdp': "SSDP (Simple Service Discovery Protocol) - протокол обнаружения служб в UPnP. Порт 1900 (UDP).",
    'bonjour': "Bonjour - технология Apple для обнаружения служб в сети. Использует mDNS (порт 5353).",
    'corba': "CORBA (Common Object Request Broker Architecture) - архитектура для распределенных объектов. Обычно порт 2809.",
    'iiop': "IIOP (Internet Inter-ORB Protocol) - протокол для CORBA через TCP/IP. Обычно порт 5353.",
    'dcom': "DCOM (Distributed Component Object Model) - технология Microsoft для распределенных объектов. Динамические порты.",
    'java-rmi': "Java RMI (Remote Method Invocation) - технология для удаленного вызова методов в Java. Порт 1099.",
    'jms': "JMS (Java Message Service) - API для обмена сообщениями в Java. Обычно поверх других протоколов.",
    'weblogic': "Oracle WebLogic Server - Java EE application server. Порт 7001.",
    'websphere': "IBM WebSphere Application Server - Java EE application server. Порт 9043.",
    'jboss': "JBoss Application Server - Java EE application server. Порт 8080, 9990.",
    'glassfish': "GlassFish - Java EE application server. Порт 4848 (администрирование), 8080 (приложения).",
    'jenkins': "Jenkins - сервер непрерывной интеграции. Порт 8080.",
    'git': "Git - система контроля версий. SSH (порт 22) или Git protocol (порт 9418).",
    'svn': "Subversion - система контроля версий. Порт 3690.",
    'cvs': "CVS (Concurrent Versions System) - система контроля версий. Порт 2401.",
    'bugzilla': "Bugzilla - система отслеживания ошибок. Обычно порт 80/443.",
    'jira': "Jira - система отслеживания задач и проектов. Обычно порт 80/443.",
    'confluence': "Confluence - wiki и платформа для совместной работы. Обычно порт 80/443.",
    'bitcoin': "Bitcoin - криптовалюта. Порт 8333.",
    'ethereum': "Ethereum - блокчейн-платформа. Порт 30303.",
    'tor': "Tor - сеть для анонимного доступа. Порт 9050 (SOCKS), 9051 (control).",
    'i2p': "I2P - анонимная сеть. Порт 7654 (router).",
    'openvpn': "OpenVPN - решение для VPN. Обычно порт 1194 (UDP).",
    'pptp': "PPTP (Point-to-Point Tunneling Protocol) - VPN протокол. Порт 1723 (TCP).",
    'l2tp': "L2TP (Layer 2 Tunneling Protocol) - VPN протокол. Порт 1701 (UDP).",
    'wireguard': "WireGuard - современный VPN протокол. Обычно порт 51820 (UDP).",
    'squid': "Squid - прокси-сервер. Порт 3128.",
    'haproxy': "HAProxy - балансировщик нагрузки. Обычно порты 80, 443, 8080.",
    'nginx': "Nginx - веб-сервер и обратный прокси. Обычно порты 80, 443.",
    'apache': "Apache HTTP Server - веб-сервер. Обычно порты 80, 443, 8080.",
    'iis': "IIS (Internet Information Services) - веб-сервер от Microsoft. Обычно порты 80, 443.",
    'lighttpd': "Lighttpd - легковесный веб-сервер. Обычно порты 80, 443.",
    'caddy': "Caddy - современный веб-сервер с автоматическим HTTPS. Обычно порты 80, 443.",
    'traefik': "Traefik - обратный прокси и балансировщик нагрузки. Обычно порты 80, 443, 8080.",
    'envoy': "Envoy - прокси-сервер для сервисных сеток. Обычно порты 80, 443, 9901 (admin).",
    'istio-gateway': "Istio Gateway - шлюз для сервисной сетки Istio. Обычно порты 80, 443.",
    'kong': "Kong - API Gateway. Обычно порты 8000 (proxy), 8001 (admin).",
    'tyk': "Tyk - API Gateway. Обычно порты 8080 (gateway), 3000 (dashboard).",
    'wordpress': "Wordpress - система управления контентом. Обычно порты 80, 443.",
    'drupal': "Drupal - система управления контентом. Обычно порты 80, 443.",
    'joomla': "Joomla - система управления контентом. Обычно порты 80, 443.",
    'magento': "Magento - платформа электронной коммерции. Обычно порты 80, 443.",
    'prestashop': "PrestaShop - платформа электронной коммерции. Обычно порты 80, 443.",
    'woocommerce': "WooCommerce - плагин электронной коммерции для WordPress. Обычно порты 80, 443.",
    'shopify': "Shopify - облачная платформа электронной коммерции. Обычно порты 80, 443.",
    'opencart': "OpenCart - платформа электронной коммерции. Обычно порты 80, 443.",
    'oscommerce': "osCommerce - платформа электронной коммерции. Обычно порты 80, 443.",
    'phpbb': "phpBB - система форумов. Обычно порты 80, 443.",
    'vbulletin': "vBulletin - система форумов. Обычно порты 80, 443.",
    'discourse': "Discourse - современная платформа для форумов. Обычно порты 80, 443.",
    'flarum': "Flarum - современная платформа для форумов. Обычно порты 80, 443.",
    'nextcloud': "Nextcloud - платформа для совместной работы. Обычно порты 80, 443.",
    'owncloud': "ownCloud - платформа для совместной работы. Обычно порты 80, 443.",
    'seafile': "Seafile - платформа для синхронизации файлов. Обычно порты 80, 443, 8082.",
    'syncthing': "Syncthing - децентрализованная синхронизация файлов. Порт 22000 (transfer), 21027 (discovery).",
    'resilio': "Resilio Sync (ранее BitTorrent Sync) - синхронизация файлов. Порт 8888.",
    'bittorrent': "BitTorrent - протокол для файлообмена. Обычно порты 6881-6889.",
    'utorrent': "μTorrent - клиент BitTorrent. Обычно порт 8080 (Web UI).",
    'transmission': "Transmission - клиент BitTorrent. Обычно порт 9091 (Web UI).",
    'deluge': "Deluge - клиент BitTorrent. Обычно порт 8112 (Web UI).",
    'qbittorrent': "qBittorrent - клиент BitTorrent. Обычно порт 8080 (Web UI).",
    'emule': "eMule - файлообменная сеть. Порт 4662 (TCP), 4672 (UDP).",
    'gnutella': "Gnutella - файлообменная сеть. Обычно порт 6346.",
    'direct-connect': "Direct Connect - файлообменная сеть. Обычно порт 411.",
    'apple-itunes': "Apple iTunes - медиа-плеер и магазин. Порт 3689 (DAAP).",
    'spotify': "Spotify - стриминговый сервис музыки. Использует различные порты.",
    'plex': "Plex - медиа-сервер. Порт 32400.",
    'emby': "Emby - медиа-сервер. Порт 8096.",
    'jellyfin': "Jellyfin - медиа-сервер. Порт 8096.",
    'kodi': "Kodi - медиа-центр. Обычно порт 8080 (Web UI).",
    'vlc': "VLC - медиа-плеер. Может использовать порты для стриминга.",
    'oscam': "OSCam - сервер для кардшаринга. Обычно порт 8888.",
    'cccam': "CCcam - протокол для кардшаринга. Обычно порт 12000.",
    'satip': "SAT>IP - сервер для спутникового TV over IP. Порт 1900 (UPnP), 8001 (RTSP).",
    'tvheadend': "Tvheadend - сервер для IPTV. Порт 9981 (Web UI), 9982 (HTSP).",
    'vlc-http': "VLC HTTP interface - веб-интерфейс VLC. Обычно порт 8080.",
    'shoutcast': "SHOUTcast - сервер для интернет-радио. Порт 8000.",
    'icecast': "Icecast - сервер для потокового вещания. Порт 8000.",
    'darwin': "Darwin Streaming Server - сервер для потокового видео от Apple. Порт 7070 (RTSP), 6970 (HTTP).",
    'quicktime': "QuickTime - медиа-технология от Apple. Использует порты для стриминга.",
    'realmedia': "RealMedia - медиа-формат от RealNetworks. Порт 554 (RTSP).",
    'windows-media': "Windows Media Services - сервер для потокового вещания от Microsoft. Порт 1755 (MMS).",
    'silverlight': "Silverlight - технология от Microsoft для Rich Internet Applications. Использует порты для стриминга.",
    'flash': "Adobe Flash - технология для Rich Internet Applications. Использует порты для RTMP.",
    'rtmp': "RTMP (Real Time Messaging Protocol) - протокол для потокового вещания. Порт 1935.",
    'rtmps': "RTMPS - защищенная версия RTMP. Порт 1935 с SSL/TLS.",
    'rtmpe': "RTMPE - шифрованная версия RTMP. Порт 1935.",
    'rtmpt': "RTMPT - RTMP через HTTP. Обычно порт 80.",
    'rtmfp': "RTMFP (Real Time Media Flow Protocol) - протокол для P2P коммуникации. Порт 1935.",
    'hls': "HLS (HTTP Live Streaming) - протокол для потокового вещания от Apple. Использует HTTP (порты 80, 443).",
    'dash': "DASH (Dynamic Adaptive Streaming over HTTP) - протокол для адаптивного стриминга. Использует HTTP (порты 80, 443).",
    'smooth-streaming': "Smooth Streaming - протокол для адаптивного стриминга от Microsoft. Использует HTTP (порты 80, 443).",
    'hds': "HDS (HTTP Dynamic Streaming) - протокол для адаптивного стриминга от Adobe. Использует HTTP (порты 80, 443).",
    'mms': "MMS (Microsoft Media Server) - протокол для потокового вещания от Microsoft. Порт 1755.",
    'mmst': "MMST - MMS через TCP. Порт 1755.",
    'mmsh': "MMSH - MMS через HTTP. Обычно порт 80.",
    'webcam': "Webcam - общее обозначение для веб-камер. Могут использовать различные протоколы и порты.",
    'axis-camera': "Axis Camera - сетевая камера. Обычно порты 80, 443, 554.",
    'hikvision': "Hikvision - сетевая камера. Обычно порты 80, 443, 554.",
    'dahua': "Dahua - сетевая камера. Обычно порты 80, 443, 554.",
    'sony-camera': "Sony Camera - сетевая камера. Обычно порты 80, 443, 554.",
    'canon-camera': "Canon Camera - сетевая камера. Обычно порты 80, 443, 554.",
    'foscam': "Foscam - сетевая камера. Обычно порты 80, 443, 554.",
    'd-link-camera': "D-Link Camera - сетевая камера. Обычно порты 80, 443, 554.",
    'tp-link-camera': "TP-Link Camera - сетевая камера. Обычно порты 80, 443, 554.",
    'ubiquiti-camera': "Ubiquiti Camera - сетевая камера. Обычно порты 80, 443, 554.",
    'vivotek-camera': "Vivotek Camera - сетевая камера. Обычно порты 80, 443, 554.",
    'mobotix-camera': "Mobotix Camera - сетевая камера. Обычно порты 80, 443, 554.",
    'bosch-camera': "Bosch Camera - сетевая камера. Обычно порты 80, 443, 554.",
    'samsung-camera': "Samsung Camera - сетевая камера. Обычно порты 80, 443, 554.",
    'panasonic-camera': "Panasonic Camera - сетевая камера. Обычно порты 80, 443, 554.",
    'cisco-camera': "Cisco Camera - сетевая камера. Обычно порты 80, 443, 554.",
    'avtech-camera': "Avtech Camera - сетевая камера. Обычно порты 80, 443, 554.",
    'geovision-camera': "Geovision Camera - сетевая камера. Обычно порты 80, 443, 554.",
    'qsee-camera': "Q-See Camera - сетевая камера. Обычно порты 80, 443, 554.",
    'night-owl-camera': "Night Owl Camera - сетевая камера. Обычно порты 80, 443, 554.",
    'swann-camera': "Swann Camera - сетевая камера. Обычно порты 80, 443, 554.",
    'lorex-camera': "Lorex Camera - сетевая камера. Обычно порты 80, 443, 554.",
    'annke-camera': "Annke Camera - сетевая камера. Обычно порты 80, 443, 554.",
    'reolink-camera': "Reolink Camera - сетевая камера. Обычно порты 80, 443, 554.",
    'ezviz-camera': "Ezviz Camera - сетевая камера. Обычно порты 80, 443, 554.",
    'imou-camera': "Imou Camera - сетевая камера. Обычно порты 80, 443, 554.",
    'droidcam': "DroidCam - использование телефона как веб-камеры. Обычно порт 4747.",
    'ip-webcam': "IP Webcam - приложение для трансляции с камеры телефона. Обычно порт 8080.",
    'yawcam': "Yawcam - веб-камера и стриминг. Обычно порт 8081.",
    'security-spy': "SecuritySpy - система видеонаблюдения для Mac. Обычно порты 80, 443, 8000.",
    'blue-iris': "Blue Iris - система видеонаблюдения для Windows. Обычно порты 80, 443, 8080.",
    'zoneminder': "ZoneMinder - система видеонаблюдения с открытым исходным кодом. Обычно порты 80, 443.",
    'shinobi': "Shinobi - система видеонаблюдения с открытым исходным кодом. Обычно порты 80, 443.",
    'kerberos-io': "Kerberos.io - система видеонаблюдения с открытым исходным кодом. Обычно порты 80, 443.",
    'motion': "Motion - детектор движения и видеозапись. Обычно порт 8080.",
    'motioneye': "MotionEye - веб-интерфейс для Motion. Обычно порт 8765.",
    'ispy': "iSpy - система видеонаблюдения с открытым исходным кодом. Обычно порты 80, 443.",
    'contacam': "ContaCam - система видеонаблюдения для Windows. Обычно порт 8080.",
    'webcamxp': "WebcamXP - программное обеспечение для веб-камер. Обычно порт 8080.",
    'yawcam': "Yawcam - веб-камера и стриминг. Обычно порт 8081.",
    'manycam': "ManyCam - виртуальная веб-камера. Обычно порты для стриминга.",
    'camera-fi': "CameraFi - использование телефона как веб-камеры. Обычно порты для Wi-Fi.",
    'ivideon': "Ivideon - облачная система видеонаблюдения. Обычно порты 80, 443.",
    'atlas-iot': "Atlas IoT - платформа для интернета вещей. Обычно порты 80, 443.",
    'aws-iot': "AWS IoT - облачная платформа для интернета вещей от Amazon. Обычно порты 80, 443, 8883.",
    'azure-iot': "Azure IoT - облачная платформа для интернета вещей от Microsoft. Обычно порты 80, 443, 8883.",
    'google-cloud-iot': "Google Cloud IoT - облачная платформа для интернета вещей от Google. Обычно порты 80, 443, 8883.",
    'ibm-watson-iot': "IBM Watson IoT - облачная платформа для интернета вещей от IBM. Обычно порты 80, 443.",
    'oracle-iot': "Oracle IoT - облачная платформа для интернета вещей от Oracle. Обычно порты 80, 443.",
    'sap-iot': "SAP IoT - платформа для интернета вещей от SAP. Обычно порты 80, 443.",
    'cisco-iot': "Cisco IoT - решения для интернета вещей от Cisco. Использует различные порты.",
    'bosch-iot': "Bosch IoT - платформа для интернета вещей от Bosch. Обычно порты 80, 443.",
    'siemens-iot': "Siemens IoT - решения для интернета вещей от Siemens. Использует различные порты.",
    'ge-predix': "GE Predix - промышленная платформа интернета вещей. Обычно порты 80, 443.",
    'ptc-thingworx': "PTC ThingWorx - платформа для интернета вещей. Обычно порты 80, 443.",
    'aws-iot-core': "AWS IoT Core - сервис для управления устройствами интернета вещей от Amazon. Обычно порты 80, 443, 8883.",
    'azure-iot-hub': "Azure IoT Hub - сервис для управления устройствами интернета вещей от Microsoft. Обычно порты 80, 443, 8883.",
    'google-cloud-iot-core': "Google Cloud IoT Core - сервис для управления устройствами интернета вещей от Google. Обычно порты 80, 443, 8883.",
    'ibm-iot-foundation': "IBM IoT Foundation - сервис для управления устройствами интернета вещей от IBM. Обычно порты 80, 443.",
    'oracle-iot-cloud-service': "Oracle IoT Cloud Service - сервис для управления устройствами интернета вещей от Oracle. Обычно порты 80, 443.",
    'aws-greengrass': "AWS Greengrass - локальная обработка для интернета вещей от Amazon. Использует различные порты.",
    'azure-iot-edge': "Azure IoT Edge - локальная обработка для интернета вещей от Microsoft. Использует различные порты.",
    'google-cloud-iot-edge': "Google Cloud IoT Edge - локальная обработка для интернета вещей от Google. Использует различные порты.",
    'aws-iot-analytics': "AWS IoT Analytics - аналитика для интернета вещей от Amazon. Обычно порты 80, 443.",
    'azure-iot-central': "Azure IoT Central - SaaS решение для интернета вещей от Microsoft. Обычно порты 80, 443.",
    'google-cloud-iot-analytics': "Google Cloud IoT Analytics - аналитика для интернета вещей от Google. Обычно порты 80, 443.",
    'ibm-iot-platform': "IBM IoT Platform - платформа для интернета вещей от IBM. Обычно порты 80, 443.",
    'oracle-iot-asset-monitoring': "Oracle IoT Asset Monitoring - мониторинг активов для интернета вещей от Oracle. Обычно порты 80, 443.",
    'aws-iot-sitewise': "AWS IoT SiteWise - мониторинг промышленных данных от Amazon. Обычно порты 80, 443.",
    'azure-iot-solution-accelerators': "Azure IoT Solution Accelerators - готовые решения для интернета вещей от Microsoft. Обычно порты 80, 443.",
    'google-cloud-iot-core-ble': "Google Cloud IoT Core BLE - поддержка Bluetooth Low Energy в Google Cloud IoT. Использует Bluetooth.",
    'aws-iot-1-click': "AWS IoT 1-Click - простые устройства интернета вещей от Amazon. Обычно порты 80, 443.",
    'azure-iot-device-simulation': "Azure IoT Device Simulation - симуляция устройств интернета вещей от Microsoft. Обычно порты 80, 443.",
    'google-cloud-iot-device-sdk': "Google Cloud IoT Device SDK - SDK для устройств интернета вещей от Google. Использует различные порты.",
    'aws-iot-device-defender': "AWS IoT Device Defender - безопасность устройств интернета вещей от Amazon. Обычно порты 80, 443.",
    'azure-iot-security': "Azure IoT Security - безопасность интернета вещей от Microsoft. Обычно порты 80, 443.",
    'google-cloud-iot-security': "Google Cloud IoT Security - безопасность интернета вещей от Google. Обычно порты 80, 443.",
    'mqtt': "MQTT (Message Queuing Telemetry Transport) - легковесный протокол для интернета вещей. Порт 1883 (незащищенный), 8883 (MQTTS).",
    'mqtts': "MQTTS - защищенная версия MQTT. Порт 8883.",
    'coap': "CoAP (Constrained Application Protocol) - протокол для ограниченных устройств интернета вещей. Порт 5683 (UDP).",
    'coaps': "CoAPS - защищенная версия CoAP. Порт 5684 (UDP).",
    'lwm2m': "LwM2M (Lightweight M2M) - протокол для управления устройствами интернета вещей. Обычно порт 5683 (CoAP).",
    'opc-ua': "OPC UA (Open Platform Communications Unified Architecture) - промышленный протокол для автоматизации. Порт 4840.",
    'amqp-iot': "AMQP для интернета вещей - версия AMQP для ограниченных устройств. Обычно порт 5672.",
    'http-iot': "HTTP для интернета вещей - облегченная версия HTTP для устройств. Обычно порты 80, 443.",
    'websocket-iot': "WebSocket для интернета вещей - использование WebSocket для устройств. Обычно порты 80, 443.",
    'zigbee': "Zigbee - протокол для беспроводных сетей с низким энергопотреблением. Использует радиочастоты 2.4 ГГц.",
    'zwave': "Z-Wave - протокол для умного дома. Использует радиочастоты 800-900 МГц.",
    'bluetooth': "Bluetooth - технология беспроводной связи на коротких расстояниях. Использует радиочастоты 2.4 ГГц.",
    'bluetooth-le': "Bluetooth Low Energy - энергоэффективная версия Bluetooth. Использует радиочастоты 2.4 ГГц.",
    'thread': "Thread - протокол для умного дома на основе IPv6. Использует радиочастоты 2.4 ГГц.",
    'matter': "Matter - стандарт для умного дома. Использует различные транспорты (Wi-Fi, Thread, Ethernet).",
    'homekit': "HomeKit - платформа для умного дома от Apple. Использует различные протоколы.",
    'alexa-smart-home': "Alexa Smart Home - платформа для умного дома от Amazon. Обычно порты 80, 443.",
    'google-smart-home': "Google Smart Home - платформа для умного дома от Google. Обычно порты 80, 443.",
    'samsung-smartthings': "Samsung SmartThings - платформа для умного дома. Обычно порты 80, 443.",
    'ifttt': "IFTTT (If This Then That) - платформа для автоматизации. Обычно порты 80, 443.",
    'openhab': "openHAB - платформа для умного дома с открытым исходным кодом. Обычно порт 8080.",
    'home-assistant': "Home Assistant - платформа для умного дома с открытым исходным кодом. Обычно порт 8123.",
    'domoticz': "Domoticz - система домашней автоматизации. Обычно порт 8080.",
    'homebridge': "Homebridge - эмулятор HomeKit для неподдерживаемых устройств. Обычно порт 51826.",
    'hassio': "Hass.io (теперь Home Assistant OS) - операционная система для умного дома. Обычно порт 8123.",
    'node-red': "Node-RED - инструмент для программирования интернета вещей. Обычно порт 1880.",
    'mosquitto': "Mosquitto - брокер MQTT с открытым исходным кодом. Порт 1883 (незащищенный), 8883 (MQTTS).",
    'emqx': "EMQX - брокер MQTT с высокой производительностью. Порт 1883 (незащищенный), 8883 (MQTTS).",
    'hivemq': "HiveMQ - брокер MQTT для предприятий. Порт 1883 (незащищенный), 8883 (MQTTS).",
    'aws-iot-core-mqtt': "AWS IoT Core MQTT - брокер MQTT от Amazon. Обычно порты 80, 443, 8883.",
    'azure-iot-hub-mqtt': "Azure IoT Hub MQTT - брокер MQTT от Microsoft. Обычно порты 80, 443, 8883.",
    'google-cloud-iot-core-mqtt': "Google Cloud IoT Core MQTT - брокер MQTT от Google. Обычно порты 80, 443, 8883.",
    'ibm-watson-iot-mqtt': "IBM Watson IoT MQTT - брокер MQTT от IBM. Обычно порты 80, 443, 8883.",
    'oracle-iot-cloud-mqtt': "Oracle IoT Cloud MQTT - брокер MQTT от Oracle. Обычно порты 80, 443, 8883.",
    'kura': "Eclipse Kura - платформа для шлюзов интернета вещей. Обычно порт 443.",
    'thingsboard': "ThingsBoard - платформа для управления устройствами интернета вещей. Обычно порт 8080.",
    'mainflux': "Mainflux - платформа для интернета вещей с открытым исходным кодом. Обычно порты 80, 443.",
    'devicehive': "DeviceHive - платформа для интернета вещей. Обычно порты 80, 443.",
    'wso2-iot': "WSO2 IoT Server - платформа для интернета вещей. Обычно порты 80, 443.",
    'kaa': "Kaa IoT Platform - платформа для интернета вещей. Обычно порты 80, 443.",
    'thingworx': "ThingWorx - платформа для интернета вещей от PTC. Обычно порты 80, 443.",
    'cumulocity': "Cumulocity IoT - платформа для интернета вещей от Software AG. Обычно порты 80, 443.",
    'xively': "Xively - платформа для интернета вещей. Обычно порты 80, 443.",
    'carriots': "Carriots - платформа для интернета вещей. Обычно порты 80, 443.",
    'evrythng': "EVRYTHNG - платформа для интернета вещей. Обычно порты 80, 443.",
    'artik': "Samsung ARTIK Cloud - платформа для интернета вещей. Обычно порты 80, 443.",
    'bosch-iot-suite': "Bosch IoT Suite - платформа для интернета вещей от Bosch. Обычно порты 80, 443.",
    'siemens-mindsphere': "Siemens MindSphere - промышленная платформа интернета вещей. Обычно порты 80, 443.",
    'ge-predix-cloud': "GE Predix Cloud - промышленная платформа интернета вещей. Обычно порты 80, 443.",
    'ptc-thingworx-platform': "PTC ThingWorx Platform - платформа для интернета вещей. Обычно порты 80, 443.",
    'aws-iot-sitewise-gateway': "AWS IoT SiteWise Gateway - шлюз для промышленных данных от Amazon. Обычно порты 80, 443.",
    'azure-iot-edge-runtime': "Azure IoT Edge Runtime - среда выполнения для Azure IoT Edge. Использует различные порты.",
    'google-cloud-iot-edge-runtime': "Google Cloud IoT Edge Runtime - среда выполнения для Google Cloud IoT Edge. Использует различные порты.",
    'balena': "Balena - платформа для управления устройствами интернета вещей. Обычно порты 80, 443.",
    'resinio': "Resin.io (теперь Balena) - платформа для развертывания на устройствах. Обычно порты 80, 443.",
    'ubios': "Ubiquiti UNMS - система управления сетевыми устройствами. Обычно порт 443.",
    'unifi': "Ubiquiti UniFi - система управления сетями. Обычно порт 8443.",
    'omada': "TP-Link Omada - система управления сетями. Обычно порт 8043.",
    'aruba-central': "Aruba Central - облачная система управления сетями. Обычно порты 80, 443.",
    'cisco-dna-center': "Cisco DNA Center - система управления сетями. Обычно порт 443.",
    'meraki': "Cisco Meraki - облачная система управления сетями. Обычно порты 80, 443.",
    'fortinet-fortigate': "Fortinet FortiGate - межсетевой экран. Обычно порт 443.",
    'paloalto-panorama': "Palo Alto Panorama - система управления межсетевыми экранами. Обычно порт 443.",
    'checkpoint-smartconsole': "Check Point SmartConsole - система управления безопасностью. Обычно порт 443.",
    'sophos-central': "Sophos Central - облачная система управления безопасностью. Обычно порты 80, 443.",
    'kaspersky-security-center': "Kaspersky Security Center - система управления безопасностью. Обычно порт 13299.",
    'symantec-endpoint-protection': "Symantec Endpoint Protection - антивирусное решение. Обычно порт 8014.",
    'mcafee-epo': "McAfee ePO - система управления безопасностью. Обычно порт 8443.",
    'trend-micro-control-manager': "Trend Micro Control Manager - система управления безопасностью. Обычно порт 4343.",
    'crowdstrike-falcon': "CrowdStrike Falcon - платформа безопасности. Обычно порты 80, 443.",
    'carbon-black': "VMware Carbon Black - платформа безопасности. Обычно порты 80, 443.",
    'cylance': "BlackBerry Cylance - антивирусное решение. Обычно порты 80, 443.",
    'sentinelone': "SentinelOne - платформа безопасности. Обычно порты 80, 443.",
    'fireeye': "FireEye - платформа безопасности. Обычно порты 80, 443.",
    'cybereason': "Cybereason - платформа безопасности. Обычно порты 80, 443.",
    'darktrace': "Darktrace - система ИИ для безопасности. Обычно порты 80, 443.",
    'varonis': "Varonis - платформа для защиты данных. Обычно порты 80, 443.",
    'proofpoint': "Proofpoint - платформа для защиты email. Обычно порты 80, 443.",
    'mimecast': "Mimecast - платформа для защиты email. Обычно порты 80, 443.",
    'barracuda': "Barracuda - решения безопасности. Обычно порты 80, 443.",
    'sonicwall': "SonicWall - межсетевые экраны. Обычно порт 443.",
    'watchguard': "WatchGuard - межсетевые экраны. Обычно порт 443.",
    'juniper-netscreen': "Juniper NetScreen - межсетевые экраны. Обычно порт 443.",
    'citrix-netscaler': "Citrix NetScaler - балансировщик нагрузки. Обычно порты 80, 443.",
    'f5-bigip': "F5 BIG-IP - балансировщик нагрузки. Обычно порты 80, 443.",
    'avi-networks': "Avi Networks - балансировщик нагрузки. Обычно порты 80, 443.",
    'nginx-plus': "NGINX Plus - балансировщик нагрузки. Обычно порты 80, 443.",
    'haproxy-enterprise': "HAProxy Enterprise - балансировщик нагрузки. Обычно порты 80, 443.",
    'aws-elb': "AWS ELB (Elastic Load Balancing) - балансировщик нагрузки от Amazon. Обычно порты 80, 443.",
    'azure-load-balancer': "Azure Load Balancer - балансировщик нагрузки от Microsoft. Обычно порты 80, 443.",
    'google-cloud-load-balancing': "Google Cloud Load Balancing - балансировщик нагрузки от Google. Обычно порты 80, 443.",
    'oracle-cloud-load-balancer': "Oracle Cloud Load Balancer - балансировщик нагрузки от Oracle. Обычно порты 80, 443.",
    'ibm-cloud-load-balancer': "IBM Cloud Load Balancer - балансировщик нагрузки от IBM. Обычно порты 80, 443.",
    'alibaba-cloud-load-balancer': "Alibaba Cloud Load Balancer - балансировщик нагрузки от Alibaba. Обычно порты 80, 443.",
    'digitalocean-load-balancer': "DigitalOcean Load Balancer - балансировщик нагрузки от DigitalOcean. Обычно порты 80, 443.",
    'linode-load-balancer': "Linode Load Balancer - балансировщик нагрузки от Linode. Обычно порты 80, 443.",
    'vultr-load-balancer': "Vultr Load Balancer - балансировщик нагрузки от Vultr. Обычно порты 80, 443.",
    'ovh-load-balancer': "OVH Load Balancer - балансировщик нагрузки от OVH. Обычно порты 80, 443.",
    'hetzner-load-balancer': "Hetzner Load Balancer - балансировщик нагрузки от Hetzner. Обычно порты 80, 443.",
    'scaleway-load-balancer': "Scaleway Load Balancer - балансировщик нагрузки от Scaleway. Обычно порты 80, 443.",
    'upcloud-load-balancer': "UpCloud Load Balancer - балансировщик нагрузки от UpCloud. Обычно порты 80, 443.",
    'rackspace-load-balancer': "Rackspace Load Balancer - балансировщик нагрузки от Rackspace. Ожидается порты 80, 443.",
    'joyent-load-balancer': "Joyent Load Balancer - балансировщик нагрузки от Joyent. Ожидается порты 80, 443.",
    'exoscale-load-balancer': "Exoscale Load Balancer - балансировщик нагрузки от Exoscale. Ожидается порты 80, 443.",
    'cloudsigma-load-balancer': "CloudSigma Load Balancer - балансировщик нагрузки от CloudSigma. Ожидается порты 80, 443.",
    'gcore-load-balancer': "G-Core Labs Load Balancer - балансировщик нагрузки от G-Core Labs. Ожидается порты 80, 443.",
    'selectel-load-balancer': "Selectel Load Balancer - балансировщик нагрузки от Selectel. Ожидается порты 80, 443.",
    'beget-load-balancer': "Beget Load Balancer - балансировщик нагрузки от Beget. Ожидается порты 80, 443.",
    'timeweb-load-balancer': "Timeweb Load Balancer - балансировщик нагрузки от Timeweb. Ожидается порты 80, 443.",
    'sprinthost-load-balancer': "Sprinthost Load Balancer - балансировщик нагрузки от Sprinthost. Ожидается порты 80, 443.",
    'reg-ru-load-balancer': "Reg.ru Load Balancer - балансировщик нагрузки от Reg.ru. Ожидается порты 80, 443.",
    'nic-ru-load-balancer': "NIC.ru Load Balancer - балансировщик нагрузки от NIC.ru. Ожидается порты 80, 443.",
    'masterhost-load-balancer': "Masterhost Load Balancer - балансировщик нагрузки от Masterhost. Ожидается порты 80, 443.",
    'firstvds-load-balancer': "FirstVDS Load Balancer - балансировщик нагрузки от FirstVDS. Ожидается порты 80, 443.",
    'hosting-load-balancer': "Hosting Load Balancer - балансировщик нагрузки от Hosting. Ожидается порты 80, 443.",
    'javarush-load-balancer': "JavaRush Load Balancer - балансировщик нагрузки от JavaRush. Ожидается порты 80, 443.",
    'ukrhost-load-balancer': "UkrHost Load Balancer - балансировщик нагрузки от UkrHost. Ожидается порты 80, 443.",
    'flops-load-balancer': "FLOPS Load Balancer - балансировщик нагрузки от FLOPS. Ожидается порты 80, 443.",
    'citynetwork-load-balancer': "City Network Load Balancer - балансировщик нагрузки от City Network. Ожидается порты 80, 443.",
    'serverclub-load-balancer': "ServerClub Load Balancer - балансировщик нагрузки от ServerClub. Ожидается порты 80, 443.",
    'itldc-load-balancer': "ITLDC Load Balancer - балансировщик нагрузки от ITLDC. Ожидается порты 80, 443.",
    'deltahost-load-balancer': "DeltaHost Load Balancer - балансировщик нагрузки от DeltaHost. Ожидается порты 80, 443.",
    'zomro-load-balancer': "Zomro Load Balancer - балансировщик нагрузки от Zomro. Ожидается порты 80, 443.",
    'hostpro-load-balancer': "HostPro Load Balancer - балансировщик нагрузки от HostPro. Ожидается порты 80, 443.",
    'tucha-load-balancer': "Tucha Load Balancer - балансировщик нагрузки от Tucha. Ожидается порты 80, 443.",
    'datalane-load-balancer': "Datalane Load Balancer - балансировщик нагрузки от Datalane. Ожидается порты 80, 443.",
    'xelent-load-balancer': "Xelent Load Balancer - балансировщик нагрузки от Xelent. Ожидается порты 80, 443.",
    'clouding-load-balancer': "Clouding Load Balancer - балансировщик нагрузки от Clouding. Ожидается порты 80, 443.",
    'aruba-cloud-load-balancer': "Aruba Cloud Load Balancer - балансировщик нагрузки от Aruba Cloud. Ожидается порты 80, 443.",
    'krystal-load-balancer': "Krystal Load Balancer - балансировщик нагрузки от Krystal. Ожидается порты 80, 443.",
    'fasthosts-load-balancer': "Fasthosts Load Balancer - балансировщик нагрузки от Fasthosts. Ожидается порты 80, 443.",
    'heartinternet-load-balancer': "Heart Internet Load Balancer - балансировщик нагрузки от Heart Internet. Ожидается порты 80, 443.",
    'lcn-load-balancer': "LCN Load Balancer - балансировщик нагрузки от LCN. Ожидается порты 80, 443.",
    'namesco-load-balancer': "Namesco Load Balancer - балансировщик нагрузки от Namesco. Ожидается порты 80, 443.",
    'one-load-balancer': "One.com Load Balancer - балансировщик нагрузки от One.com. Ожидается порты 80, 443.",
    'siteground-load-balancer': "SiteGround Load Balancer - балансировщик нагрузки от SiteGround. Ожидается порты 80, 443.",
    'tsohost-load-balancer': "TSOHost Load Balancer - балансировщик нагрузки от TSOHost. Ожидается порты 80, 443.",
    'vidahost-load-balancer': "Vidahost Load Balancer - балансировщик нагрузки от Vidahost. Ожидается порты 80, 443.",
    'webhostingbuzz-load-balancer': "WebHostingBuzz Load Balancer - балансировщик нагрузки от WebHostingBuzz. Ожидается порты 80, 443.",
    'westhost-load-balancer': "WestHost Load Balancer - балансировщик нагрузки от WestHost. Ожидается порты 80, 443.",
    'wiredtree-load-balancer': "WiredTree Load Balancer - балансировщик нагрузки от WiredTree. Ожидается порты 80, 443.",
    'wpengine-load-balancer': "WP Engine Load Balancer - балансировщик нагрузки от WP Engine. Ожидается порты 80, 443.",
    'znet-load-balancer': "ZNet Load Balancer - балансировщик нагрузки от ZNet. Ожидается порты 80, 443.",
    'zunicom-load-balancer': "Zunicom Load Balancer - балансировщик нагрузки от Zunicom. Ожидается порты 80, 443.",
    'acugis-load-balancer': "Acugis Load Balancer - балансировщик нагрузки от Acugis. Ожидается порты 80, 443.",
    'a2hosting-load-balancer': "A2 Hosting Load Balancer - балансировщик нагрузки от A2 Hosting. Ожидается порты 80, 443.",
    'accuwebhosting-load-balancer': "AccuWeb Hosting Load Balancer - балансировщик нагрузки от AccuWeb Hosting. Ожидается порты 80, 443.",
    'bluehost-load-balancer': "Bluehost Load Balancer - балансировщик нагрузки от Bluehost. Ожидается порты 80, 443.",
    'dreamhost-load-balancer': "DreamHost Load Balancer - балансировщик нагрузки от DreamHost. Ожидается порты 80, 443.",
    'fatcow-load-balancer': "FatCow Load Balancer - балансировщик нагрузки от FatCow. Ожидается порты 80, 443.",
    'godaddy-load-balancer': "GoDaddy Load Balancer - балансировщик нагрузки от GoDaddy. Ожидается порты 80, 443.",
    'hostgator-load-balancer': "HostGator Load Balancer - балансировщик нагрузки от HostGator. Ожидается порты 80, 443.",
    'hostmonster-load-balancer': "HostMonster Load Balancer - балансировщик нагрузки от HostMonster. Ожидается порты 80, 443.",
    'inmotion-load-balancer': "InMotion Load Balancer - балансировщик нагрузки от InMotion. Ожидается порты 80, 443.",
    'ipage-load-balancer': "iPage Load Balancer - балансировщик нагрузки от iPage. Ожидается порты 80, 443.",
    'justhost-load-balancer': "JustHost Load Balancer - балансировщик нагрузки от JustHost. Ожидается порты 80, 443.",
    'liquidweb-load-balancer': "Liquid Web Load Balancer - балансировщик нагрузки от Liquid Web. Ожидается порты 80, 443.",
    'media-temple-load-balancer': "Media Temple Load Balancer - балансировщик нагрузки от Media Temple. Ожидается порты 80, 443.",
    'wp-engine-load-balancer': "WP Engine Load Balancer - балансировщик нагрузки от WP Engine. Ожидается порты 80, 443.",
    'kinsta-load-balancer': "Kinsta Load Balancer - балансировщик нагрузки от Kinsta. Ожидается порты 80, 443.",
    'pantheon-load-balancer': "Pantheon Load Balancer - балансировщик нагрузки от Pantheon. Ожидается порты 80, 443.",
    'acquia-load-balancer': "Acquia Load Balancer - балансировщик нагрузки от Acquia. Ожидается порты 80, 443.",
    'platform-sh-load-balancer': "Platform.sh Load Balancer - балансировщик нагрузки от Platform.sh. Ожидается порты 80, 443.",
    'heroku-load-balancer': "Heroku Load Balancer - балансировщик нагрузки от Heroku. Ожидается порты 80, 443.",
    'netlify-load-balancer': "Netlify Load Balancer - балансировщик нагрузки от Netlify. Ожидается порты 80, 443.",
    'vercel-load-balancer': "Vercel Load Balancer - балансировщик нагрузки от Vercel. Ожидается порты 80, 443.",
    'cloudflare-load-balancer': "Cloudflare Load Balancer - балансировщик нагрузки от Cloudflare. Ожидается порты 80, 443.",
    'fastly-load-balancer': "Fastly Load Balancer - балансировщик нагрузки от Fastly. Ожидается порты 80, 443.",
    'akamai-load-balancer': "Akamai Load Balancer - балансировщик нагрузки от Akamai. Ожидается порты 80, 443.",
    'imperva-load-balancer': "Imperva Load Balancer - балансировщик нагрузки от Imperva. Ожидается порты 80, 443.",
    'sucuri-load-balancer': "Sucuri Load Balancer - балансировщик нагрузки от Sucuri. Ожидается порты 80, 443.",
    'incapsula-load-balancer': "Incapsula Load Balancer - балансировщик нагрузки от Incapsula. Ожидается порты 80, 443.",
    'cloudfront-load-balancer': "Amazon CloudFront Load Balancer - балансировщик нагрузки от Amazon CloudFront. Ожидается порты 80, 443.",
    'azure-cdn-load-balancer': "Azure CDN Load Balancer - балансировщик нагрузки от Azure CDN. Ожидается порты 80, 443.",
    'google-cdn-load-balancer': "Google CDN Load Balancer - балансировщик нагрузки от Google CDN. Ожидается порты 80, 443.",
    'oracle-cdn-load-balancer': "Oracle CDN Load Balancer - балансировщик нагрузки от Oracle CDN. Ожидается порты 80, 443.",
    'ibm-cdn-load-balancer': "IBM CDN Load Balancer - балансировщик нагрузки от IBM CDN. Ожидается порты 80, 443.",
    'alibaba-cdn-load-balancer': "Alibaba CDN Load Balancer - балансировщик нагрузки от Alibaba CDN. Ожидается порты 80, 443.",
    'stackpath-load-balancer': "StackPath Load Balancer - балансировщик нагрузки от StackPath. Ожидается порты 80, 443.",
    'keycdn-load-balancer': "KeyCDN Load Balancer - балансировщик нагрузки от KeyCDN. Ожидается порты 80, 443.",
    'bunnycdn-load-balancer': "BunnyCDN Load Balancer - балансировщик нагрузки от BunnyCDN. Ожидается порты 80, 443.",
    'cdn77-load-balancer': "CDN77 Load Balancer - балансировщик нагрузки от CDN77. Ожидается порты 80, 443.",
    'gcore-cdn-load-balancer': "G-Core Labs CDN Load Balancer - балансировщик нагрузки от G-Core Labs CDN. Ожидается порты 80, 443.",
    'belugacdn-load-balancer': "BelugaCDN Load Balancer - балансировщик нагрузки от BelugaCDN. Ожидается порты 80, 443.",
    'cachefly-load-balancer': "CacheFly Load Balancer - балансировщик нагрузки от CacheFly. Ожидается порты 80, 443.",
    'maxcdn-load-balancer': "MaxCDN Load Balancer - балансировщик нагрузки от MaxCDN. Ожидается порты 80, 443.",
    'cdnnetworks-load-balancer': "CDNetworks Load Balancer - балансировщик нагрузки от CDNetworks. Ожидается порты 80, 443.",
    'chinacache-load-balancer': "ChinaCache Load Balancer - балансировщик нагрузки от ChinaCache. Ожидается порты 80, 443.",
    'wangsu-load-balancer': "Wangsu Load Balancer - балансировщик нагрузки от Wangsu. Ожидается порты 80, 443.",
    'tencent-cloud-cdn-load-balancer': "Tencent Cloud CDN Load Balancer - балансировщик нагрузки от Tencent Cloud CDN. Ожидается порты 80, 443.",
    'baidu-cloud-cdn-load-balancer': "Baidu Cloud CDN Load Balancer - балансировщик нагрузки от Baidu Cloud CDN. Ожидается порты 80, 443.",
    'huawei-cloud-cdn-load-balancer': "Huawei Cloud CDN Load Balancer - балансировщик нагрузки от Huawei Cloud CDN. Ожидается порты 80, 443.",
    'ucloud-cdn-load-balancer': "UCloud CDN Load Balancer - балансировщик нагрузки от UCloud CDN. Ожидается порты 80, 443.",
    'qingcloud-cdn-load-balancer': "QingCloud CDN Load Balancer - балансировщик нагрузки от QingCloud CDN. Ожидается порты 80, 443.",
    'jd-cloud-cdn-load-balancer': "JD Cloud CDN Load Balancer - балансировщик нагрузки от JD Cloud CDN. Ожидается порты 80, 443.",
    'sina-cloud-cdn-load-balancer': "Sina Cloud CDN Load Balancer - балансировщик нагрузки от Sina Cloud CDN. Ожидается порты 80, 443.",
    'netease-cloud-cdn-load-balancer': "Netease Cloud CDN Load Balancer - балансировщик нагрузки от Netease Cloud CDN. Ожидается порты 80, 443.",
    'datapipe-load-balancer': "Datapipe Load Balancer - балансировщик нагрузки от Datapipe. Ожидается порты 80, 443.",
    'singlehop-load-balancer': "SingleHop Load Balancer - балансировщик нагрузки от SingleHop. Ожидается порты 80, 443.",
    'peer1-load-balancer': "Peer1 Load Balancer - балансировщик нагрузки от Peer1. Ожидается порты 80, 443.",
    'softlayer-load-balancer': "SoftLayer Load Balancer - балансировщик нагрузки от SoftLayer. Ожидается порты 80, 443.",
    'ibm-cloud-pak-load-balancer': "IBM Cloud Pak Load Balancer - балансировщик нагрузки от IBM Cloud Pak. Ожидается порты 80, 443.",
    'red-hat-openshift-load-balancer': "Red Hat OpenShift Load Balancer - балансировщик нагрузки от Red Hat OpenShift. Ожидается порты 80, 443.",
    'suse-caasp-load-balancer': "SUSE CaaSP Load Balancer - балансировщик нагрузки от SUSE CaaSP. Ожидается порты 80, 443.",
    'canonical-kubernetes-load-balancer': "Canonical Kubernetes Load Balancer - балансировщик нагрузки от Canonical Kubernetes. Ожидается порты 80, 443.",
    'vmware-tanzu-load-balancer': "VMware Tanzu Load Balancer - балансировщик нагрузки от VMware Tanzu. Ожидается порты 80, 443.",
    'pivotal-cloud-foundry-load-balancer': "Pivotal Cloud Foundry Load Balancer - балансировщик нагрузки от Pivotal Cloud Foundry. Ожидается порты 80, 443.",
    'cloudfoundry-load-balancer': "Cloud Foundry Load Balancer - балансировщик нагрузки от Cloud Foundry. Ожидается порты 80, 443.",
    'apache-cloudstack-load-balancer': "Apache CloudStack Load Balancer - балансировщик нагрузки от Apache CloudStack. Ожидается порты 80, 443.",
    'openstack-load-balancer': "OpenStack Load Balancer - балансировщик нагрузки от OpenStack. Ожидается порты 80, 443.",
    'eucalyptus-load-balancer': "Eucalyptus Load Balancer - балансировщик нагрузки от Eucalyptus. Ожидается порты 80, 443.",
    'cloudstack-load-balancer': "CloudStack Load Balancer - балансировщик нагрузки от CloudStack. Ожидается порты 80, 443.",
    'opennebula-load-balancer': "OpenNebula Load Balancer - балансировщик нагрузки от OpenNebula. Ожидается порты 80, 443.",
    'proxmox-load-balancer': "Proxmox Load Balancer - балансировщик нагрузки от Proxmox. Ожидается порты 80, 443.",
    'xen-server-load-balancer': "Xen Server Load Balancer - балансировщик нагрузки от Xen Server. Ожидается порты 80, 443.",
    'citrix-xenserver-load-balancer': "Citrix XenServer Load Balancer - балансировщик нагрузки от Citrix XenServer. Ожидается порты 80, 443.",
    'vmware-vsphere-load-balancer': "VMware vSphere Load Balancer - балансировщик нагрузки от VMware vSphere. Ожидается порты 80, 443.",
    'microsoft-hyper-v-load-balancer': "Microsoft Hyper-V Load Balancer - балансировщик нагрузки от Microsoft Hyper-V. Ожидается порты 80, 443.",
    'kvm-load-balancer': "KVM Load Balancer - балансировщик нагрузки от KVM. Ожидается порты 80, 443.",
    'qemu-load-balancer': "QEMU Load Balancer - балансировщик нагрузки от QEMU. Ожидается порты 80, 443.",
    'virtualbox-load-balancer': "VirtualBox Load Balancer - балансировщик нагрузки от VirtualBox. Ожидается порты 80, 443.",
    'parallels-load-balancer': "Parallels Load Balancer - балансировщик нагрузки от Parallels. Ожидается порты 80, 443.",
    'docker-swarm-load-balancer': "Docker Swarm Load Balancer - балансировщик нагрузки от Docker Swarm. Ожидается порты 80, 443.",
    'docker-compose-load-balancer': "Docker Compose Load Balancer - балансировщик нагрузки от Docker Compose. Ожидается порты 80, 443.",
    'podman-load-balancer': "Podman Load Balancer - балансировщик нагрузки от Podman. Ожидается порты 80, 443.",
    'lxd-load-balancer': "LXD Load Balancer - балансировщик нагрузки от LXD. Ожидается порты 80, 443.",
    'rkt-load-balancer': "rkt Load Balancer - балансировщик нагрузки от rkt. Ожидается порты 80, 443.",
    'cri-o-load-balancer': "CRI-O Load Balancer - балансировщик нагрузки от CRI-O. Ожидается порты 80, 443.",
    'containerd-load-balancer': "containerd Load Balancer - балансировщик нагрузки от containerd. Ожидается порты 80, 443.",
    'gvisor-load-balancer': "gVisor Load Balancer - балансировщик нагрузки от gVisor. Ожидается порты 80, 443.",
    'kata-containers-load-balancer': "Kata Containers Load Balancer - балансировщик нагрузки от Kata Containers. Ожидается порты 80, 443.",
    'firecracker-load-balancer': "Firecracker Load Balancer - балансировщик нагрузки от Firecracker. Ожидается порты 80, 443.",
    'nvidia-docker-load-balancer': "NVIDIA Docker Load Balancer - балансировщик нагрузки от NVIDIA Docker. Ожидается порты 80, 443.",
    'aws-ecs-load-balancer': "AWS ECS Load Balancer - балансировщик нагрузки от AWS Elastic Container Service. Ожидается порты 80, 443.",
    'aws-eks-load-balancer': "AWS EKS Load Balancer - балансировщик нагрузки от AWS Elastic Kubernetes Service. Ожидается порты 80, 443.",
    'azure-aks-load-balancer': "Azure AKS Load Balancer - балансировщик нагрузки от Azure Kubernetes Service. Ожидается порты 80, 443.",
    'google-gke-load-balancer': "Google GKE Load Balancer - балансировщик нагрузки от Google Kubernetes Engine. Ожидается порты 80, 443.",
    'oracle-oke-load-balancer': "Oracle OKE Load Balancer - балансировщик нагрузки от Oracle Kubernetes Engine. Ожидается порты 80, 443.",
    'ibm-iks-load-balancer': "IBM IKS Load Balancer - балансировщик нагрузки от IBM Kubernetes Service. Ожидается порты 80, 443.",
    'alibaba-ack-load-balancer': "Alibaba ACK Load Balancer - балансировщик нагрузки от Alibaba Container Service for Kubernetes. Ожидается порты 80, 443.",
    'tencent-tke-load-balancer': "Tencent TKE Load Balancer - балансировщик нагрузки от Tencent Kubernetes Engine. Ожидается порты 80, 443.",
    'baidu-bce-load-balancer': "Baidu BCE Load Balancer - балансировщик нагрузки от Baidu Cloud Engine. Ожидается порты 80, 443.",
    'huawei-cce-load-balancer': "Huawei CCE Load Balancer - балансировщик нагрузки от Huawei Cloud Container Engine. Ожидается порты 80, 443.",
    'digitalocean-doks-load-balancer': "DigitalOcean DOKS Load Balancer - балансировщик нагрузки от DigitalOcean Kubernetes. Ожидается порты 80, 443.",
    'linode-lke-load-balancer': "Linode LKE Load Balancer - балансировщик нагрузки от Linode Kubernetes Engine. Ожидается порты 80, 443.",
    'vultr-kubernetes-load-balancer': "Vultr Kubernetes Load Balancer - балансировщик нагрузки от Vultr Kubernetes. Ожидается порты 80, 443.",
    'ovh-kubernetes-load-balancer': "OVH Kubernetes Load Balancer - балансировщик нагрузки от OVH Kubernetes. Ожидается порты 80, 443.",
    'scaleway-kapsule-load-balancer': "Scaleway Kapsule Load Balancer - балансировщик нагрузки от Scaleway Kapsule. Ожидается порты 80, 443.",
    'upcloud-kubernetes-load-balancer': "UpCloud Kubernetes Load Balancer - балансировщик нагрузки от UpCloud Kubernetes. Ожидается порты 80, 443.",
    'hetzner-kubernetes-load-balancer': "Hetzner Kubernetes Load Balancer - балансировщик нагрузки от Hetzner Kubernetes. Ожидается порты 80, 443.",
    'packet-kubernetes-load-balancer': "Packet Kubernetes Load Balancer - балансировщик нагрузки от Packet Kubernetes. Ожидается порты 80, 443.",
    'equinix-metal-kubernetes-load-balancer': "Equinix Metal Kubernetes Load Balancer - балансировщик нагрузки от Equinix Metal Kubernetes. Ожидается порты 80, 443.",
    'ibm-cloud-kubernetes-load-balancer': "IBM Cloud Kubernetes Load Balancer - балансировщик нагрузки от IBM Cloud Kubernetes. Ожидается порты 80, 443.",
    'oracle-cloud-kubernetes-load-balancer': "Oracle Cloud Kubernetes Load Balancer - балансировщик нагрузки от Oracle Cloud Kubernetes. Ожидается порты 80, 443.",
    'alibaba-cloud-kubernetes-load-balancer': "Alibaba Cloud Kubernetes Load Balancer - балансировщик нагрузки от Alibaba Cloud Kubernetes. Ожидается порты 80, 443.",
    'tencent-cloud-kubernetes-load-balancer': "Tencent Cloud Kubernetes Load Balancer - балансировщик нагрузки от Tencent Cloud Kubernetes. Ожидается порты 80, 443.",
    'baidu-cloud-kubernetes-load-balancer': "Baidu Cloud Kubernetes Load Balancer - балансировщик нагрузки от Baidu Cloud Kubernetes. Ожидается порты 80, 443.",
    'huawei-cloud-kubernetes-load-balancer': "Huawei Cloud Kubernetes Load Balancer - балансировщик нагрузки от Huawei Cloud Kubernetes. Ожидается порты 80, 443.",
    'ucloud-kubernetes-load-balancer': "UCloud Kubernetes Load Balancer - балансировщик нагрузки от UCloud Kubernetes. Ожидается порты 80, 443.",
    'qingcloud-kubernetes-load-balancer': "QingCloud Kubernetes Load Balancer - балансировщик нагрузки от QingCloud Kubernetes. Ожидается порты 80, 443.",
    'jd-cloud-kubernetes-load-balancer': "JD Cloud Kubernetes Load Balancer - балансировщик нагрузки от JD Cloud Kubernetes. Ожидается порты 80, 443.",
    'sina-cloud-kubernetes-load-balancer': "Sina Cloud Kubernetes Load Balancer - балансировщик нагрузки от Sina Cloud Kubernetes. Ожидается порты 80, 443.",
    'netease-cloud-kubernetes-load-balancer': "Netease Cloud Kubernetes Load Balancer - балансировщик нагрузки от Netease Cloud Kubernetes. Ожидается порты 80, 443.",
}

def check_dependencies():
    if not TQDM_AVAILABLE:
        print("Предупреждение: tqdm не установлен. Для красивого прогресс-бара установите: pip install tqdm")
    
    import sys
    if sys.version_info < (3, 6):
        print(" Ошибка: Требуется Python 3.6 или выше")
        sys.exit(1)

PROTOCOL_SIGNATURES = {
    'rpc': {
        'ports': [111, 135],
        'response_patterns': [b'rpc', b'portmapper'],
        'confidence': 0.8
    },
    'netbios': {
        'ports': [137, 138, 139],
        'response_patterns': [b'NETBIOS', b'SMB'],
        'confidence': 0.7
    },
    'ldaps': {
        'ports': [636],
        'ssl': True,
        'response_patterns': [b'LDAP'],
        'confidence': 0.9
    },
    'kerberos': {
        'ports': [88, 464, 749],
        'response_patterns': [b'kerberos', b'KRB5'],
        'confidence': 0.8
    },
    'http': {
        'ports': [80, 8080, 8000, 8008, 8081, 8888, 8443],
        'request': b"GET / HTTP/1.0\r\nHost: example.com\r\n\r\n",
        'response_patterns': [b'HTTP/', b'Server:', b'Content-Type:'],
        'confidence': 0.9
    },
    'https': {
        'ports': [443, 8443],
        'ssl': True,
        'response_patterns': [b'HTTP/', b'Server:'],
        'confidence': 0.95
    },
    'ssh': {
        'ports': [22, 2222, 22222],
        'response_patterns': [b'SSH-', b'OpenSSH'],
        'confidence': 0.98
    },
    'ftp': {
        'ports': [21, 2121],
        'response_patterns': [b'220', b'FTP', b'vsFTPd', b'ProFTPD'],
        'confidence': 0.95
    },
    'smtp': {
        'ports': [25, 587, 465],
        'response_patterns': [b'220', b'ESMTP', b'SMTP', b'Postfix', b'Exim'],
        'confidence': 0.9
    },
    'dns': {
        'ports': [53],
        'udp': True,
        'request': b'\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03',
        'response_patterns': [b'version.bind'],
        'confidence': 0.85
    },
    'mysql': {
        'ports': [3306, 3307, 33060],
        'response_patterns': [b'mysql', b'MariaDB'],
        'confidence': 0.9
    },
    'redis': {
        'ports': [6379, 63790],
        'response_patterns': [b'REDIS'],
        'confidence': 0.95
    },
    'mongodb': {
        'ports': [27017, 27018, 27019],
        'response_patterns': [],
        'confidence': 0.8
    },
    'rdp': {
        'ports': [3389, 33890],
        'response_patterns': [b'\x03\x00\x00'],
        'confidence': 0.9
    },
    'vnc': {
        'ports': [5900, 5901, 5902],
        'response_patterns': [b'RFB'],
        'confidence': 0.95
    },
    'elasticsearch': {
        'ports': [9200, 9300],
        'response_patterns': [b'"cluster_name"', b'"version"'],
        'confidence': 0.9
    },
    'postgresql': {
        'ports': [5432, 5433],
        'response_patterns': [b'PostgreSQL', b'user'],
        'confidence': 0.9
    },
    'telnet': {
        'ports': [23, 2323],
        'response_patterns': [b'Telnet', b'login:', b'Password:'],
        'confidence': 0.85
    },
    'sip': {
        'ports': [5060, 5061],
        'response_patterns': [b'SIP/2.0', b'INVITE', b'REGISTER'],
        'confidence': 0.8
    },
    'snmp': {
        'ports': [161, 162],
        'udp': True,
        'response_patterns': [b'public', b'private'],
        'confidence': 0.7
    },
    'imap': {
        'ports': [143, 993],
        'response_patterns': [b'OK', b'IMAP', b'CAPABILITY'],
        'confidence': 0.85
    },
    'pop3': {
        'ports': [110, 995],
        'response_patterns': [b'+OK', b'POP3'],
        'confidence': 0.85
    },
    'ldap': {
        'ports': [389, 636],
        'response_patterns': [b'LDAP'],
        'confidence': 0.8
    },
    'ntp': {
        'ports': [123],
        'udp': True,
        'response_patterns': [],
        'confidence': 0.7
    },
    'http-alt': {
        'ports': [8080, 8081, 8088, 8888],
        'request': b"GET / HTTP/1.0\r\nHost: example.com\r\n\r\n",
        'response_patterns': [b'HTTP/', b'Server:', b'Content-Type:'],
        'confidence': 0.85
    },
    'tomcat': {
        'ports': [8080, 8009, 8443],
        'response_patterns': [b'Apache Tomcat', b'Tomcat'],
        'confidence': 0.9
    },
    'proxy': {
        'ports': [3128, 8080, 8118, 8123],
        'response_patterns': [b'Proxy', b'Squid'],
        'confidence': 0.8
    }
}

class ProtocolDetector:   
    def __init__(self, timeout=3):
        self.timeout = timeout
        self.detection_cache = {}
    
    def detect_protocol(self, target, port, protocol='tcp'):
        cache_key = f"{target}:{port}:{protocol}"
        if cache_key in self.detection_cache:
            return self.detection_cache[cache_key]
        
        detected = self._perform_detection(target, port, protocol)
        self.detection_cache[cache_key] = detected
        return detected
    
    def _perform_detection(self, target, port, protocol):
        best_match = {'service': 'unknown', 'confidence': 0, 'banner': ''}
    
        for proto_name, signature in PROTOCOL_SIGNATURES.items():
            if signature.get('udp', False) and protocol != 'udp':
                continue
            if not signature.get('udp', False) and protocol == 'udp':
                continue
            
            if signature['ports'] and port not in signature['ports']:
                continue
            
            confidence, banner = self._check_protocol(target, port, proto_name, signature, protocol)
            
            if confidence > best_match['confidence']:
                best_match = {
                    'service': proto_name,
                    'confidence': confidence,
                    'banner': banner
                }
        
        if best_match['confidence'] < 0.6:
            fallback = self._fallback_detection(target, port, protocol)
            if fallback['confidence'] > best_match['confidence']:
                best_match = fallback
        
        return best_match
    
    def _check_protocol(self, target, port, proto_name, signature, protocol):
        try:
            if protocol == 'tcp':
                return self._check_tcp_protocol(target, port, proto_name, signature)
            else:
                return self._check_udp_protocol(target, port, proto_name, signature)
        except Exception as e:
            return 0, f"Ошибка проверки: {str(e)}"
    
    def _check_tcp_protocol(self, target, port, proto_name, signature):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(self.timeout)
            
            try:
                sock.connect((target, port))
                
                if signature.get('ssl', False):
                    try:
                        context = ssl.create_default_context()
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                        with context.wrap_socket(sock, server_hostname=target) as ssock:
                            cert = ssock.getpeercert()
                            if cert:
                                return signature['confidence'], f"SSL: {cert}"
                    except Exception as e:
                        pass
                
                if 'request' in signature:
                    sock.send(signature['request'])
                    time.sleep(0.5)
                
                banner = self._receive_banner(sock)
                
                if signature['response_patterns']:
                    for pattern in signature['response_patterns']:
                        if pattern in banner:
                            return signature['confidence'], banner[:200].decode('utf-8', errors='ignore')
                
                if banner:
                    return signature['confidence'] * 0.8, banner[:200].decode('utf-8', errors='ignore')
                
                return signature['confidence'] * 0.6, ""
                
            except Exception as e:
                return 0, f"Ошибка подключения: {str(e)}"
    
    def _check_udp_protocol(self, target, port, proto_name, signature):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(self.timeout)
            
            try:
                if 'request' in signature:
                    sock.sendto(signature['request'], (target, port))
                try:
                    data, addr = sock.recvfrom(1024)
                    banner = data.decode('utf-8', errors='ignore')
                    
                    if signature['response_patterns']:
                        for pattern in signature['response_patterns']:
                            if pattern in data:
                                return signature['confidence'], banner[:200]
                    
                    return signature['confidence'] * 0.7, banner[:200]
                except socket.timeout:
                    return signature['confidence'] * 0.5, "Нет ответа"
                    
            except Exception as e:
                return 0, f"Ошибка UDP: {str(e)}"
    
    def _receive_banner(self, sock):
        banner = b""
        try:
            sock.settimeout(1.0)
            while True:
                chunk = sock.recv(1024)
                if not chunk:
                    break
                banner += chunk
                if len(banner) > 4096:  
                    break
        except:
            pass
        return banner
    
    def _fallback_detection(self, target, port, protocol):
        try:
            if protocol == 'tcp':
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(2)
                    sock.connect((target, port))
                    
                    banner = self._receive_banner(sock)
                    if banner:
                        banner_str = banner.decode('utf-8', errors='ignore').lower()
                        
                        if any(word in banner_str for word in ['http', 'html', 'server']):
                            return {'service': 'http', 'confidence': 0.7, 'banner': banner[:200].decode('utf-8', errors='ignore')}
                        elif any(word in banner_str for word in ['ssh', 'openssh']):
                            return {'service': 'ssh', 'confidence': 0.8, 'banner': banner[:200].decode('utf-8', errors='ignore')}
                        elif any(word in banner_str for word in ['ftp', 'vsftpd']):
                            return {'service': 'ftp', 'confidence': 0.8, 'banner': banner[:200].decode('utf-8', errors='ignore')}
                        elif any(word in banner_str for word in ['smtp', 'esmtp']):
                            return {'service': 'smtp', 'confidence': 0.7, 'banner': banner[:200].decode('utf-8', errors='ignore')}
                        elif any(word in banner_str for word in ['imap']):
                            return {'service': 'imap', 'confidence': 0.7, 'banner': banner[:200].decode('utf-8', errors='ignore')}
                        elif any(word in banner_str for word in ['pop3']):
                            return {'service': 'pop3', 'confidence': 0.7, 'banner': banner[:200].decode('utf-8', errors='ignore')}
                        
                        return {'service': 'unknown-tcp', 'confidence': 0.5, 'banner': banner[:200].decode('utf-8', errors='ignore')}
                    
                    return {'service': 'unknown-tcp', 'confidence': 0.3, 'banner': ''}
            
            else: 
                return {'service': 'unknown-udp', 'confidence': 0.2, 'banner': ''}
                
        except Exception as e:
            return {'service': 'unknown', 'confidence': 0, 'banner': f'Ошибка: {str(e)}'}

class Yoxiko:
    def __init__(self, max_threads=200, timeout=2, verbose=False, log_file=None, info_mode=False):
        self.max_threads = max_threads
        self.timeout = timeout
        self.verbose = verbose
        self.info_mode = info_mode
        self.detector = ProtocolDetector(timeout=timeout)
        self.results = []
        self.blacklist_ips = set()
        self.blacklist_ports = set()
        self.stats = {
            'hosts_scanned': 0,
            'ports_scanned': 0,
            'open_ports_found': 0,
            'start_time': None,
            'end_time': None
        }
        
        self.setup_logging(log_file)
        self.load_blacklists()

    def setup_logging(self, log_file=None):
        self.logger = logging.getLogger('yoxiko')
        self.logger.setLevel(logging.DEBUG if self.verbose else logging.INFO)
        
        formatter = logging.Formatter(
            '%(levelname)s - %(message)s'
        )
        
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)
        
        if log_file:
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)

    def load_blacklists(self):
        try:
            if os.path.exists('blacklist_ips.txt'):
                with open('blacklist_ips.txt', 'r', encoding='utf-8') as f:
                    self.blacklist_ips = set(line.strip() for line in f if line.strip() and not line.startswith('#'))
                self.logger.info(f"Загружено {len(self.blacklist_ips)} IP в черный список")
        except Exception as e:
            self.logger.warning(f"Ошибка загрузки черного списка IP: {e}")
            
        try:
            if os.path.exists('blacklist_ports.txt'):
                with open('blacklist_ports.txt', 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            try:
                                self.blacklist_ports.add(int(line))
                            except ValueError:
                                pass
                self.logger.info(f"Загружено {len(self.blacklist_ports)} портов в черный список")
        except Exception as e:
            self.logger.warning(f"Ошибка загрузки черного списка портов: {e}")

    def is_blacklisted(self, target, port):
        return target in self.blacklist_ips or port in self.blacklist_ports

    def print_banner(self):
        print(" Yoxiko - сканер портов \n\n\n ")

    def log(self, message, level="INFO"):
        if level == "INFO":
            self.logger.info(message)
        elif level == "WARNING":
            self.logger.warning(message)
        elif level == "ERROR":
            self.logger.error(message)
        elif level == "DEBUG":
            self.logger.debug(message)

    def parse_ports(self, port_spec):
        ports = set()
        
        if port_spec.lower() == 'common':
            all_ports = set()
            for proto in PROTOCOL_SIGNATURES.values():
                all_ports.update(proto['ports'])
            return sorted(all_ports)[:100]  
        
        elif port_spec.lower() == 'top100':
            return list(range(1, 101)) + [443, 993, 995, 1723, 5060]
        
        elif port_spec.lower() == 'all':
            return list(range(1, 65536))
        
        elif port_spec.lower() == 'web':
            return [80, 443, 8080, 8443, 8000, 3000, 5000, 9000]
        
        elif port_spec.lower() == 'database':
            return [3306, 5432, 27017, 6379, 9200, 9300, 1521, 1433]
        
        elif port_spec.lower() == 'mail':
            return [25, 110, 143, 465, 587, 993, 995]
        
        elif port_spec.lower() == 'remote':
            return [22, 23, 3389, 5900, 5901]
        elif port_spec.lower() == 'network':
            return [53, 67, 68, 123, 161, 162, 389, 636, 1812, 1813]
        
        elif port_spec.lower() == 'fileshare':
            return [139, 445, 2049, 111, 635, 965]
        
        elif port_spec.lower() == 'virtualization':
            return [5900, 5901, 5902, 5988, 5989, 8006, 8008, 8443]
        
        elif port_spec.lower() == 'industrial':
            return [502, 102, 20000, 44818, 47808, 1911, 4900]
        
        elif port_spec.lower() == 'gaming':
            return [25565, 27015, 27016, 27017, 7777, 7778, 3074, 3478, 4379, 4380]  
        
        parts = port_spec.split(',')
        for part in parts:
            part = part.strip()
            if '-' in part:
                try:
                    start, end = map(int, part.split('-'))
                    if start > end:
                        start, end = end, start
                    ports.update(range(start, end + 1))
                except ValueError:
                    self.log(f"Неверный диапазон портов: {part}", "WARNING")
            else:
                try:
                    port = int(part)
                    if 1 <= port <= 65535:
                        ports.add(port)
                    else:
                        self.log(f"Порт вне диапазона: {port}", "WARNING")
                except ValueError:
                    self.log(f"Неверный порт: {part}", "WARNING")
        
        return sorted(ports)

    def parse_targets(self, target_spec):
        targets = set()
        
        try:
            if '/' in target_spec:
                network = ipaddress.IPv4Network(target_spec, strict=False)
                targets.update(str(ip) for ip in network.hosts())
            elif '-' in target_spec and target_spec.count('.') == 3:
                base_ip, range_part = target_spec.rsplit('.', 1)
                if '-' in range_part:
                    start, end = map(int, range_part.split('-'))
                    for i in range(start, end + 1):
                        targets.add(f"{base_ip}.{i}")
                else:
                    targets.add(target_spec)
            else:
                try:
                    ip = socket.gethostbyname(target_spec)
                    targets.add(ip)
                except socket.gaierror:
                    self.log(f"Не удалось разрешить: {target_spec}", "ERROR")
                    targets.add(target_spec)
        except Exception as e:
            self.log(f"Ошибка парсинга цели {target_spec}: {e}", "ERROR")
            targets.add(target_spec)
            
        filtered_targets = [t for t in targets if t not in self.blacklist_ips]
        if len(filtered_targets) != len(targets):
            self.log(f"Отфильтровано {len(targets) - len(filtered_targets)} целей по черному списку", "INFO")
            
        return filtered_targets

    def smart_scan(self, target, port, protocol='tcp'):
        self.stats['ports_scanned'] += 1
        
        if self.is_blacklisted(target, port):
            return None
        
        try:
            if protocol == 'tcp':
                return self._tcp_scan(target, port)
            else: 
                return self._udp_scan(target, port)
                
        except Exception as e:
            if self.verbose:
                self.log(f"Ошибка сканирования {target}:{port} - {e}", "ERROR")
            return None

    def _tcp_scan(self, target, port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(self.timeout)
            result = sock.connect_ex((target, port))
            
            if result == 0:
                detection = self.detector.detect_protocol(target, port, 'tcp')
                
                return {
                    'target': target,
                    'port': port,
                    'state': 'open',
                    'protocol': 'tcp',
                    'service': detection['service'],
                    'confidence': detection['confidence'],
                    'banner': detection['banner'],
                    'timestamp': datetime.now().isoformat()
                }
            else:
                return None

    def _udp_scan(self, target, port):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(self.timeout)
            
            try:
                sock.sendto(b'', (target, port))
                data, addr = sock.recvfrom(1024)
                detection = self.detector.detect_protocol(target, port, 'udp')
                
                return {
                    'target': target,
                    'port': port,
                    'state': 'open',
                    'protocol': 'udp',
                    'service': detection['service'],
                    'confidence': detection['confidence'],
                    'banner': detection['banner'],
                    'timestamp': datetime.now().isoformat()
                }
            except socket.timeout:
                detection = self.detector.detect_protocol(target, port, 'udp')
                if detection['confidence'] > 0.3:
                    return {
                        'target': target,
                        'port': port,
                        'state': 'open|filtered',
                        'protocol': 'udp',
                        'service': detection['service'],
                        'confidence': detection['confidence'],
                        'banner': detection['banner'],
                        'timestamp': datetime.now().isoformat()
                    }
                return None
            except Exception:
                return None

    def run_scan(self, target_spec, port_spec='common', output_file=None, 
                 protocol='tcp', timing_template=3, output_format='json'):
        self.stats['start_time'] = time.time()
        self.print_banner()
        
        self.timeout = max(0.5, 5 - timing_template)
        self.max_threads = min(1000, 50 * timing_template)
        
        targets = self.parse_targets(target_spec)
        ports = self.parse_ports(port_spec)
        
        filtered_ports = [p for p in ports if p not in self.blacklist_ports]
        if len(filtered_ports) != len(ports):
            self.log(f"Отфильтровано {len(ports) - len(filtered_ports)} портов по черному списку", "INFO")
        ports = filtered_ports
        
        print(f" Цели: {len(targets)} хост(ов)")
        print(f" Порты: {len(ports)} порт(ов)")
        print(f" Протокол: {protocol.upper()}")
        print(f" Потоки: {self.max_threads}")
        print(f" Таймаут: {self.timeout}с")
        print()
        
        all_results = []
        
        for target in targets:
            self.stats['hosts_scanned'] += 1
            self.log(f"Сканирование {target}...", "INFO")
            target_results = []
            
            port_iterator = ports
            
            completed = 0
            with ThreadPoolExecutor(max_workers=min(self.max_threads, len(ports))) as executor:
                future_to_port = {
                    executor.submit(self.smart_scan, target, port, protocol): port 
                    for port in ports
                }
                
                for future in as_completed(future_to_port):
                    result = future.result()
                    if result:
                        target_results.append(result)
                        
                        confidence_icon = "🟢" if result['confidence'] > 0.8 else "🟡" if result['confidence'] > 0.5 else "🟠"
                        banner_preview = result['banner'][:50] if result['banner'] else ''
                        
                        print(f"  {confidence_icon} {result['port']} - {result['protocol']} - {result['service']} - {banner_preview}")
                        
                        if self.info_mode:
                            description = PROTOCOL_DESCRIPTIONS.get(result['service'], PROTOCOL_DESCRIPTIONS['unknown'])
                            print(f"    {description}")
                            if result['banner']:
                                print(f"    Баннер: {result['banner'][:100]}")
                            print()
                    
                    completed += 1
            
            all_results.extend(target_results)
        
        if output_file:
            self.save_results(all_results, output_file, output_format)
        
        self.stats['end_time'] = time.time()
        duration = self.stats['end_time'] - self.stats['start_time']
        print(f"\nСканирование заняло: {duration:.2f} секунд")
        
        return all_results

    def save_results(self, results, filename, format='json'):
        try:
            if format.lower() == 'json':
                output = {
                    'scan_info': {
                        'scanner': 'Yoxiko',
                        'timestamp': datetime.now().isoformat(),
                        'duration': self.stats['end_time'] - self.stats['start_time'],
                        'stats': self.stats
                    },
                    'results': results
                }
                
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(output, f, indent=2, ensure_ascii=False)
                
            elif format.lower() == 'csv':
                with open(filename, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(['Цель', 'Порт', 'Протокол', 'Служба', 'Уверенность', 'Баннер', 'Время'])
                    for result in results:
                        writer.writerow([
                            result['target'],
                            result['port'],
                            result['protocol'],
                            result['service'],
                            f"{result['confidence']:.2f}",
                            result['banner'],
                            result['timestamp']
                        ])
                        
            elif format.lower() == 'txt':
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write("Yoxiko - Результаты сканирования\n")
                    f.write("//" * 50 + "\n\n")
                    f.write(f"Время: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"Всего найдено: {len(results)} открытых портов\n\n")
                    
                    for result in results:
                        f.write(f"{result['target']}:{result['port']} - {result['service']} ({result['confidence']:.2f})\n")
                        if result['banner']:
                            f.write(f"  Баннер: {result['banner']}\n")
                        f.write("\n")
            
            self.log(f"Результаты сохранены в: {filename} ({format})", "INFO")
            
        except Exception as e:
            self.log(f"Ошибка сохранения результатов: {e}", "ERROR")

def main():
    check_dependencies()
    
    parser = argparse.ArgumentParser(
        description='yoxiko - сканер портов',
        add_help=False
    )
    
    parser.add_argument('target', nargs='?', help='Цель сканирования')
    parser.add_argument('-p', '--ports', default='common', 
                       help='Порты для сканирования: common, top100, all, web, database, mail, remote или 80,443 или 1-100')
    parser.add_argument('-o', '--output', help='Файл для сохранения результатов')
    parser.add_argument('--format', choices=['json', 'csv', 'txt'], default='json', help='Формат вывода') 
    parser.add_argument('-u', '--udp', action='store_true', help='UDP сканирование')
    parser.add_argument('-T', '--timing', type=int, default=3, choices=range(0, 6), help='Скорость сканирования 0-5')
    parser.add_argument('--max-threads', type=int, default=200, help='Максимум потоков')
    parser.add_argument('--timeout', type=float, default=2.0, help='Таймаут подключения')
    parser.add_argument('--log', help='Файл для логов')
    parser.add_argument('-v', '--verbose', action='store_true', help='Подробный вывод')
    parser.add_argument('-info', '--info', action='store_true', help='Показать информацию о найденных службах')
    parser.add_argument('-h', '--help', action='store_true', help='Показать справку')
    parser.add_argument('--service-scan', action='store_true', 
                   help='Углубленное сканирование служб')
    parser.add_argument('--os-detection', action='store_true',
                    help='Попытка определения ОС')
    parser.add_argument('--vuln-scan', action='store_true',
                    help='Проверка известных уязвимостей')
    
    args = parser.parse_args()
    
    if args.help or not args.target:
        print("yoxiko - сканер портов")
        print()
        print("Использование: python yoxiko.py [цель] [опции]")
        print()
        print("Основные опции:")
        print("  -p ПОРТЫ      Порты: common, top100, all, web, database, mail, remote, 80,443 или 1-100")
        print("  -o ФАЙЛ       Сохранить результаты в файл")
        print("  --format      Формат вывода: json, csv, txt")
        print("  -u            UDP сканирование")
        print("  -T 0-5        Скорость сканирования")
        print("  -v            Подробный вывод")
        print("  -info         Показать информацию о найденных службах")
        print()
        print("Примеры:")
        print("  python yoxiko.py 192.168.1.1")
        print("  python yoxiko.py -p web example.com")
        print("  python yoxiko.py -p database -info 10.0.0.1")
        print("  python yoxiko.py -u -o results.json 10.0.0.0/24")
        return
    
    protocol = 'tcp'
    if args.udp:
        protocol = 'udp'
    
    scanner = Yoxiko(
        max_threads=args.max_threads,
        timeout=args.timeout,
        verbose=args.verbose,
        log_file=args.log,
        info_mode=args.info
    )
    
    try:
        results = scanner.run_scan(
            target_spec=args.target,
            port_spec=args.ports,
            output_file=args.output,
            protocol=protocol,
            timing_template=args.timing,
            output_format=args.format
        )
        
    except KeyboardInterrupt:
        print("\n Сканирование прервано")
    except Exception as e:
        print(f" Ошибка: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    main()
 