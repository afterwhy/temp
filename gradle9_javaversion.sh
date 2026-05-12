JAVA_VERSION=$(
  ./gradlew --init-script <(cat <<'EOF'
    task printJavaVersion {
      doLast {
        def v = java.toolchain.languageVersion.orNull()?.asInt() ?: 8
        logger.quiet v
      }
    }
EOF
) -q printJavaVersion 2>/dev/null | tail -n1
)
echo "Required Java version: $JAVA_VERSION"
