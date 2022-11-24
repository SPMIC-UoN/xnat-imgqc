# Gradle is too dumb to deal with changes to the schema without
# removing all cached build artifacts
rm -rf $HOME/.gradle .gradle build
./gradlew jar

