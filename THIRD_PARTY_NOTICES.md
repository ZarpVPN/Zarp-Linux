# Сторонние компоненты

Код Zarp for Linux распространяется под [MIT](LICENSE). Лицензии включённых компонентов сохраняют силу независимо от лицензии приложения.

| Компонент | Источник | Лицензия |
| --- | --- | --- |
| Zarp for Windows, основа интерфейса и поведения | [ZarpVPN/Zarp](https://github.com/ZarpVPN/Zarp) | MIT |
| Zarp for macOS, справочная реализация | [ZarpVPN/Zarp-MacOS](https://github.com/ZarpVPN/Zarp-MacOS) | MIT |
| zapret2, nfqws2, Lua-профили и шаблоны пакетов | [bol-van/zapret2](https://github.com/bol-van/zapret2) | [MIT](resources/licenses/zapret2.txt) |
| sing-box | [SagerNet/sing-box](https://github.com/SagerNet/sing-box) | [GPL-3.0-or-later](resources/licenses/sing-box.txt) |
| Xray-core | [XTLS/Xray-core](https://github.com/XTLS/Xray-core) | [MPL-2.0 и включённые GPL-компоненты](resources/licenses/xray.txt) |
| Microsoft Selawik | [microsoft/Selawik](https://github.com/microsoft/Selawik) | [SIL OFL 1.1](resources/fonts/LICENSE.txt) |
| Noto Sans Devanagari | [notofonts/devanagari](https://github.com/notofonts/devanagari) | [SIL OFL 1.1](resources/fonts/NotoSansDevanagari-OFL.txt) |
| Страновые IP-диапазоны | [ipverse/country-ip-blocks](https://github.com/ipverse/country-ip-blocks) | [CC0](https://creativecommons.org/publicdomain/zero/1.0/) |

Версии, commit zapret2, адреса архивов и их SHA-256 фиксируются в [resources/engines.json](resources/engines.json). В установленном пакете `runtime/integrity.json` содержит хеши всех исполняемых файлов, Lua-модулей и шаблонов. sing-box и Xray запускаются как отдельные программы; их лицензии и исходники доступны по ссылкам выше.

Компактный VK Initial получен из публичного шаблона zapret2. Скрипт [tools/compact-quic-fake.py](tools/compact-quic-fake.py) воспроизводит пакет на 1200 байт и проверяет сохранность полного аутентифицированного ClientHello. Он не использует ключи или учётные данные пользователя.

Приложение динамически использует PySide6/Qt и системные Lua, libnetfilter_queue, libmnl и zlib. Эти зависимости устанавливает пакетный менеджер дистрибутива; их лицензии поставляются соответствующими системными пакетами.

Лицензии и метаданные исходников шрифтов находятся в `resources/fonts/`. Segoe UI не распространяется вместе с проектом. Код GPL-приложения Zarp for Android не включён в Linux-приложение.

Cloudflare WARP является отдельным проприетарным клиентом и в пакеты Zarp не входит. Проверочный ключ репозитория Cloudflare является публичным. Cloudflare и WARP являются товарными знаками Cloudflare, Inc.; проект не связан с Cloudflare и не одобрен ею.
