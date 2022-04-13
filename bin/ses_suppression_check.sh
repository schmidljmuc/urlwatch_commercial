#!/bin/bash 
POSITIONAL_ARGS=()
while [[ $# -gt 0 ]]; do
  case $1 in
    -e|--email)
      EMAIL="$2"
      shift # past argument
      shift # past value
      ;;
    *)
      POSITIONAL_ARGS+=("$1") # save positional arg
      shift # past argument
      ;;
  esac
done

if [[ -z $EMAIL ]]; then
    echo -e "Parameter missing! Usage: sh $0 '--email user@example.org'"
else
    aws sesv2 get-suppressed-destination --email-address $EMAIL > /dev/null 2>&1
    if [[ $? == 0 ]]; then
        echo "Failure - Email address ${EMAIL} is on your suppression list."
    else
        echo "OK - Email address ${EMAIL} does not exist on your suppression list."
    fi
fi