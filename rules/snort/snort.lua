HOME_NET = 'any'
EXTERNAL_NET = 'any'

ips =
{
    rules = [[
        include rules/snort/local_ics.rules
    ]]
}

alert_csv = {}
