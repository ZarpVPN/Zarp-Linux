# Сборка и релизы

Проект собирается на Linux x86_64. Go-бинарники статические; nfqws2 собирается с библиотеками целевого дистрибутива. Пакет для новой glibc не следует устанавливать в систему со старой glibc.

## Зависимости

Установите Go 1.24 или новее и следующие пакеты.

### Ubuntu 26.04 и Debian 13

```sh
sudo apt install git build-essential pkg-config liblua5.4-dev libcap-dev libnetfilter-queue-dev libmnl-dev zlib1g-dev \
  python3 python3-yaml python3-cryptography python3-pyside6.qtwidgets python3-pyside6.qttest \
  qt6-qpa-plugins qt6-wayland fonts-dejavu-core nftables iptables iproute2 gnupg polkitd pkexec
```

### Fedora 44

```sh
sudo dnf install git gcc gcc-c++ make pkgconf-pkg-config lua-devel libcap-devel libnetfilter_queue-devel libmnl-devel zlib-devel \
  python3 python3-pyyaml python3-cryptography python3-pyside6 qt6-qtbase qt6-qtwayland \
  nftables iptables-nft iproute gnupg2 polkit rpm-build
```

### Arch Linux

```sh
sudo pacman -S --needed git base-devel lua54 libcap libnetfilter_queue libmnl zlib \
  python python-yaml python-cryptography pyside6 qt6-base qt6-wayland ttf-dejavu \
  nftables iptables iproute2 gnupg polkit
```

## Из исходников

```sh
git clone https://github.com/ZarpVPN/Zarp-Linux.git
cd Zarp-Linux
make runtime
make build
make test
make package
```

Обычный пользователь может собирать все форматы. Для Arch это обязательное условие `makepkg`; в CI сборка пакета выполняется от отдельного пользователя `zarpbuild`.

`make runtime` получает версии из [resources/engines.json](../resources/engines.json), проверяет SHA-256 архивов sing-box/Xray и фиксированный commit zapret2. Проверенные архивы кэшируются в `vendor/`. Никакие загруженные установочные скрипты не исполняются.

`make package` пересобирает nfqws2 нативно, сохраняет проверенные байты движков и создаёт `.deb`, `.rpm` или `.pkg.tar.zst` в `build/packages/`. Рядом записывается контрольная сумма. Пакет не содержит Cloudflare WARP.

Для другого каталога runtime или вывода:

```sh
bash tools/build-native-runtime.sh build/native-runtime
python3 tools/native-packages.py --runtime build/native-runtime/runtime --output build/packages/local
```

## Автоматические сборки

[GitHub Actions](../.github/workflows/build.yml) выполняет четыре независимые нативные сборки: Ubuntu 26.04, Debian 13, Fedora 44 и Arch Linux. Workflow запускается при push в `main`/`master`, pull request, вручную и при публикации тега `v*`.

Каждая сборка устанавливает свой пакет в одноразовый контейнер и проверяет Go/race, GUI от обычного пользователя, параметры zapret2 и реальную обработку пакетов в отдельном сетевом namespace. Реальный WARP-аккаунт и действующий VPN в CI не используются. Привилегии контейнера нужны для этих тестов, а `--cgroupns=host` сохраняет видимость именованной cgroup процесса для проверки перехвата API. Контейнер выполняется на одноразовой виртуальной машине GitHub.

Артефакты `package-*` содержат готовый пакет, `tests-*` содержат журналы и JSON-отчёт. Неудача одного дистрибутива не отменяет остальные проверки и запрещает публикацию релиза.

## Выпуск версии

1. Измените `Version` в [internal/core/types.go](../internal/core/types.go).
2. Проверьте изменения и отправьте commit в репозиторий.
3. Создайте тег с той же версией:

```sh
git tag v0.3.5
git push origin v0.3.5
```

Workflow проверяет точное совпадение тега и версии исходников. Поддерживаются стабильные теги `vMAJOR.MINOR.PATCH`; некорректный тег останавливает сборку до публикации.

После успешной проверки всех четырёх пакетов создаётся черновик релиза, загружаются пакеты, `SHA256SUMS` и `release-manifest.json`, затем релиз публикуется. Манифест содержит commit исходников, версии движков и суммы пакетов. Ссылки на файлы имеют постоянные имена, как `Zarp.exe` в Windows-версии.

Для публикации используется штатный `GITHUB_TOKEN`. Дополнительный PAT не нужен. Право `contents: write` получает только отдельная задача публикации; сборки работают с `contents: read`. Actions закреплены на SHA и обновляются через Dependabot.

Если загрузка прервалась и остался черновик, удалите незавершённый черновик перед повторным запуском workflow. Уже опубликованный релиз автоматически не перезаписывается.

## Границы поддержки

Нативные пакеты и интерфейс проверялись в Ubuntu, Debian, Fedora и Arch под WSL2. Это не подтверждает совместимость со всеми дистрибутивами, ARM64, musl, системами без systemd или каждой конфигурацией Wayland/SELinux.

Автоматическая установка официального WARP приложением пока доступна только через APT на Ubuntu/Debian. На Arch/Fedora требуется отдельная установка клиента.
