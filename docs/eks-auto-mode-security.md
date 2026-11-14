# Защита кластера EKS в Auto Mode: меры, риски, реализация

Источник: документация AWS из датасета `Vyber07/cyber-security` (файл `aws_pdf_chunks.json`: EKS User Guide, EKS Best Practices Guide, GuardDuty, Security Hub, Network Firewall). Документация в датасете примерно середины 2025 года.

Строки со звёздочкой (*) — не из датасета, а из знаний модели; их нужно сверить с актуальной документацией AWS.

## Что уже делает Auto Mode

Проверять, но не настраивать:

- неизменяемые AMI на Bottlerocket;
- SELinux в режиме enforcing, корневая ФС только для чтения;
- нет доступа к узлам по SSH и SSM;
- IMDSv2 с hop limit 1 (изменить нельзя);
- автозамена узлов не реже чем раз в 21 день;
- автоматические патчи.

Зона ответственности заказчика: доступ к API, права подов, сетевые политики, egress, admission-политики и обнаружение.

## Таблица мер

| Область | Мера | Риск, который закрывает | Реализация |
|---|---|---|---|
| Доступ к API | Приватный endpoint кластера | Атаки на API из интернета, перебор и утёкшие учётные данные | `endpointPublicAccess=false`, либо публичный со списком разрешённых CIDR; контроль Security Hub EKS.1 |
| Доступ к API | Access entries вместо `aws-auth`, без постоянного админа у создателя | Неотзываемый cluster-admin, неаудируемые права | `authenticationMode=API`, `bootstrapClusterCreatorAdminPermissions=false`, политики `AmazonEKSViewPolicy`/`EditPolicy` по неймспейсам |
| Доступ к API | Минимальные RBAC-права | Повышение привилегий внутри кластера | Никаких `["*"]` в Role/ClusterRole, отдельный ServiceAccount на приложение |
| Права подов | EKS Pod Identity, одна IAM-роль на приложение | Под получает права узла или соседнего сервиса | Агент Pod Identity в Auto Mode уже встроен; роль узла оставить минимальной |
| Права подов | Запрет `hostNetwork` и привилегированных подов | `hostNetwork: true` даёт поду доступ к IMDS и роли узла, обходя hop limit | Pod Security Standards уровня `restricted` на неймспейсах плюс Kyverno или Gatekeeper |
| Сеть в кластере | Сетевые политики с запретом по умолчанию | Горизонтальное перемещение между подами | ConfigMap `amazon-vpc-cni` с `enable-network-policy-controller: "true"`; в `NodeClass`: `networkPolicy: DefaultDeny`, `networkPolicyEventLogs: Enabled`; далее разрешающие NetworkPolicy по неймспейсам |
| Egress | Egress-правила в NetworkPolicy | Вывод данных, связь с C2, скачивание вредоносного кода | `policyTypes: [Egress]`, разрешить только DNS и нужные CIDR/сервисы |
| Egress | Фильтрация по доменам на периметре VPC | NetworkPolicy работает по IP, а не по именам; обход через новые адреса | AWS Network Firewall: domain list (allowlist) или Suricata-правила по `tls.sni`, маршрут из приватных подсетей через firewall |
| Egress | Приватные подсети, без публичных IP у узлов | Прямой выход в интернет мимо точек контроля | `NodeClass` с селектором только приватных подсетей; VPC endpoints для ECR, S3, STS, CloudWatch |
| Egress | Прокси для трафика самих узлов | Узел тянет образы и обновления в обход фильтра | `NodeClass`: `advancedNetworking.httpsProxy`, `noProxy`, `certificateBundles` |
| Egress* | Политики по DNS-именам и кластерные политики | Команды неймспейсов ослабляют правила; allowlist по IP не работает для SaaS | `ApplicationNetworkPolicy` с `domainNames` и `ClusterNetworkPolicy` в Auto Mode (подтверждено по актуальной документации AWS, см. ниже) |
| Egress* | DNS-фильтрация | DNS-туннелирование, резолв вредоносных доменов | Route 53 Resolver DNS Firewall на VPC |
| Данные | Шифрование секретов в etcd | Чтение секретов из бэкапа или при компрометации control plane | Envelope encryption с ключом KMS; контроль Security Hub EKS.3 |
| Данные | Шифрование дисков узлов и томов | Доступ к данным на EBS | `NodeClass`: `ephemeralStorage.kmsKeyID`; `StorageClass` с `encrypted: true` и своим KMS-ключом |
| Данные | Внешнее хранилище секретов | Секреты в манифестах и переменных окружения | AWS Secrets Manager или Vault, ротация |
| Бенчмарки | CIS-отчёт по узлам | Дрейф конфигурации ОС, недоказуемое соответствие | Раздел «Generate CIS report» в EKS User Guide: отчёт CIS Bottlerocket Benchmark с узла через debug-контейнер |
| Бенчмарки | CIS Amazon EKS Benchmark по кластеру | Небезопасные настройки kubelet, RBAC, подов | `kube-bench` периодически (Job по расписанию); control plane проверить нельзя, он за AWS |
| Бенчмарки | Непрерывный контроль конфигурации AWS | Отключили логи, открыли endpoint, устарела версия | Security Hub: EKS.1, EKS.2, EKS.3, EKS.8; правила AWS Config |
| Admission | Policy-as-code | Запуск небезопасных подов, образы из чужих реестров, отсутствие лимитов | Kyverno или OPA/Gatekeeper: разрешённые реестры, запрет `latest`, обязательные `securityContext` |
| Цепочка поставок | Подпись и сканирование образов | Подменённый или уязвимый образ | AWS Signer или cosign, проверка подписи в Kyverno; сканирование ECR через Inspector* |
| Обнаружение | Аудит-логи control plane | Нет следов при расследовании | Включить типы `api`, `audit`, `authenticator`, `controllerManager`, `scheduler` в CloudWatch; контроль EKS.8 |
| Обнаружение | GuardDuty EKS Protection и Runtime Monitoring | Незамеченная компрометация пода, майнеры, анонимный доступ к API | Обе функции поддерживают Auto Mode; дополнительно Malware Protection for EC2 для узлов |
| Обнаружение | Логи сетевых политик и VPC Flow Logs | Не видно заблокированных и аномальных соединений | `networkPolicyEventLogs: Enabled`, Flow Logs на VPC, логи Network Firewall |
| Узлы | Сократить срок жизни узла | Закрепление атакующего на узле | `expireAfter` в NodePool меньше 21 дня*; настроить PodDisruptionBudget, чтобы не блокировать замену |
| Узлы | Агенты безопасности только как DaemonSet | Кастомизация AMI невозможна, а привилегированный агент сам становится целью | Отдельный неймспейс с исключением из PSS, минимум агентов, жёсткий RBAC |
| Узлы | Изоляция чувствительных нагрузок | Побег из контейнера затрагивает соседей по узлу | Отдельные NodePool и NodeClass с taints, свои security groups и подсети |

## На чём чаще всего спотыкаются

- **Сетевые политики выключены по умолчанию.** Сначала включается контроллер через ConfigMap `amazon-vpc-cni`, затем при необходимости меняется поведение в `NodeClass`.
- **Свой `NodeClass` требует access entry** типа `EC2` для роли узла с политикой `AmazonEKSAutoNodePolicy`, иначе узлы не присоединятся к кластеру.
- **Контроль egress — это два слоя.** NetworkPolicy ограничивает поды внутри кластера, Network Firewall — весь трафик VPC по доменам. Политики не видят имён в TLS, а firewall не различает поды.

## Уточнения по актуальной документации AWS (ноябрь 2026)

Проверено по docs.aws.amazon.com, на стенде не разворачивалось.

- В Auto Mode есть `ApplicationNetworkPolicy` (egress по `domainNames`, только на узлах Auto Mode) и `ClusterNetworkPolicy` (уровни Admin и Baseline).
- Фильтрация по SNI на Network Firewall: при строгом порядке правил allowlist не добавляет запрет автоматически, нужен default action «Drop established» или «Application drop established».
- SNI заявляет клиент и его можно подделать. Закрывается настройкой Resolved IP validation в политике firewall и типом цели `AWS_ROUTE_53_RESOLVED_DOMAIN` вместе с `TLS_SNI`, либо TLS inspection.
- По умолчанию (`snatPolicy: Random`) firewall видит адрес узла, а не пода. Для разграничения по нагрузкам — отдельные NodePool/NodeClass со своими подсетями.
- Domain list фильтрует только HTTP и HTTPS; QUIC (UDP 443) нужно блокировать отдельно.
- При централизованной inspection VPC нужно добавить CIDR кластера в `HOME_NET` группы правил.

Ссылки:

- https://docs.aws.amazon.com/eks/latest/userguide/auto-net-pol.html
- https://docs.aws.amazon.com/eks/latest/userguide/create-node-class.html
- https://docs.aws.amazon.com/network-firewall/latest/developerguide/stateful-rule-groups-domain-names.html
- https://docs.aws.amazon.com/network-firewall/latest/developerguide/suricata-rule-evaluation-order.html
- https://docs.aws.amazon.com/network-firewall/latest/developerguide/route53-resolved-ip-validation.html
- https://docs.aws.amazon.com/network-firewall/latest/developerguide/tls-inspection-considerations.html
