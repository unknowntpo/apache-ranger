# Build trino plugin

This is the instruction to build trino plugin locally and in Github Actions.

## Build locally:

```
mvn -Dmaven.test.skip=true -DskipDocs -Pranger-trino-plugin -Pranger-trino-plugin,!all,!linux clean package
```

And taget will be found at:

```
ls -l target/
total 115200
drwxr-xr-x@ 3 unknowntpo  staff        96 Jul 17 11:07 antrun/
drwxr-xr-x@ 3 unknowntpo  staff        96 Jul 17 11:07 maven-shared-archive-resources/
-rw-r--r--@ 1 unknowntpo  staff  58527440 Jul 17 11:07 ranger-2.4.0-trino-plugin.tar.gz
-rw-r--r--@ 1 unknowntpo  staff         5 Jul 17 11:07 version
```

## Built in Github Action:

Add tag with prefix `v`:

```
git tag v2.4.73
```

Push tag:

```
git push --tags
```
