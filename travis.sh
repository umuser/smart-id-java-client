#!/bin/bash

# Fail on first error
set -e

echo "Is pull request: $TRAVIS_PULL_REQUEST"
echo "Tag:             $TRAVIS_TAG"
echo "JDK version:     $TRAVIS_JDK_VERSION"

if [ "$TRAVIS_PULL_REQUEST" == "false" ] && [ "$TRAVIS_TAG" != "" ] && [ "$TRAVIS_JDK_VERSION" == "openjdk17" ]; then
  echo "Starting to publish"
  ./publish.sh
  echo "Finished"
elif [ "$TRAVIS_PULL_REQUEST" == "false" ] && [ "$TRAVIS_JDK_VERSION" == "openjdk17" ]; then
  ./mvnw -DnvdApiKey="$NVD_key" org.owasp:dependency-check-maven:check
else
  ./mvnw test
  ./mvnw spotbugs:check
fi
