package com.iotics.sdk.identity.experimental;

import java.io.IOException;
import java.util.Objects;

public interface ResolverClient {
    final class Result {
        private final String content;
        private final String contentType;
        private final boolean isErr;

        public Result(String content, String contentType, boolean isErr) {
            this.content = content;
            this.contentType = contentType;
            this.isErr = isErr;
        }

        @Override
        public String toString() {
            return "Result{" +
                    "content='" + content + '\'' +
                    ", contentType='" + contentType + '\'' +
                    ", isErr=" + isErr +
                    '}';
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            Result result = (Result) o;
            return isErr == result.isErr && Objects.equals(content, result.content) && Objects.equals(contentType, result.contentType);
        }

        @Override
        public int hashCode() {
            return Objects.hash(content, contentType, isErr);
        }

        public String content() {
            return content;
        }

        public String contentType() {
            return contentType;
        }

        public boolean isErr() {
            return isErr;
        }
    }

    Result discover(String did) throws IOException;
}
