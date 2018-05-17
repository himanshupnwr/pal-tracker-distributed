#!/usr/bin/env bash

set -e

declare -a apps=( "Registration" "Allocations" "Backlog" "Timesheets" )
declare -a ports=( 8883 8881 8882 8884 )

function usage() {
    echo -e "\nStarts a specific server or all servers if the name is omitted.\n\nUsage:\n\n$0 [$(join_by ' | ' "${apps[@]}")]\n"
    exit 1
}

function join_by {
    local d=$1
    shift
    echo -n "$1"
    shift
    printf "%s" "${@/#/$d}"
}

function start_server() {
    export DISABLE_AUTH=true
    dotnet run --project "Applications/${1}Server/${1}Server.csproj" --urls "http://*:${2}"
}

if [[ -n "$1" ]] && [[ ! " ${apps[@]} " =~ " ${1} " ]]
    then usage
fi

trap "kill 0" EXIT
    for i in ${!apps[@]}
    do
        app=${apps[$i]}
        if [[ "$1" = "$app" ]] || [ -z "$1" ]
        then
            start_server "$app" "${ports[$i]}" &
        fi
    done
wait