import { defineProject } from "vitest/config";

export default defineProject({
  test: {
    name: "console",
    environment: "node",
    include: ["src/**/*.test.ts"],
  },
});
