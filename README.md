# Privileges
# Утилита для систем Windows

### Проверяет наличие привилегий SeDebugPrivilege, SeBackUpPrivilege и SeRestorePrivilege в токене.
### В случае если они есть и находятся в состоянии disabled - переводит их в состояние enabled. Если они включены, то утилита ничего не делает.
### Если их нет, то она  добавляет их в токен и создает процесс с этим токеном
