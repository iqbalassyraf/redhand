# M4.7b: the tuning and frozen split of the real documents

**Written and committed before any Radar rule is changed** (the commit time is the proof that the split came first). Plan: `docs/plans/phase4-m4-7b-quieter-rules.md` (decision F-D5: under 5% strong findings on the frozen set; the block gate stays at 3%).

## The rule
Take the first 120 repositories of `REPOS` in `scripts/radar_real_life_proof.py` (the 120 that proof script runs; the 17 after them are not used). Sort their names `owner/name` by `sha256(name.encode("utf-8")).hexdigest()` ascending. The first 60 are the **tuning set**; the other 60 are the **frozen set**. The rule is deterministic, so nobody can choose favourable repositories after seeing results.

`scripts/radar_real_documents_split.py` recomputes this split and `agentwall/tests/test_m4_7b_split.py` fails if this file and the script ever disagree or if the two sets overlap, so the lists below cannot be edited by hand.

## Rules of use
- The **tuning set** may be fetched and read, only into an untracked folder outside the repository (decision P4-D10: third-party text is never committed).
- The **frozen set** is measured only by a counts-only script that scans text in memory and prints numbers. Nobody opens, prints or stores a frozen document, and nobody opens a document that was flagged in it. It is measured **once**, after the rules are final.
- Only names and counts are committed.

## Tuning set (60)
- `dart-lang/sdk`
- `pytorch/pytorch`
- `ansible/ansible`
- `tokio-rs/tokio`
- `docker/compose`
- `vercel/next.js`
- `home-assistant/core`
- `fastify/fastify`
- `dotnet/aspnetcore`
- `vim/vim`
- `prometheus/prometheus`
- `nodejs/node`
- `vuejs/core`
- `elastic/elasticsearch`
- `symfony/symfony`
- `openai/openai-python`
- `JuliaLang/julia`
- `TanStack/query`
- `lodash/lodash`
- `python/cpython`
- `webpack/webpack`
- `apple/swift`
- `vitest-dev/vitest`
- `openssl/openssl`
- `encode/httpx`
- `sveltejs/svelte`
- `gradle/gradle`
- `cypress-io/cypress`
- `flutter/flutter`
- `laravel/framework`
- `prisma/prisma`
- `sequelize/sequelize`
- `date-fns/date-fns`
- `tensorflow/tensorflow`
- `microsoft/TypeScript`
- `neovim/neovim`
- `expressjs/express`
- `reduxjs/redux`
- `mui/material-ui`
- `tmux/tmux`
- `serde-rs/serde`
- `ocaml/ocaml`
- `apache/kafka`
- `postgres/postgres`
- `hashicorp/terraform`
- `langchain-ai/langchain`
- `traefik/traefik`
- `nestjs/nest`
- `prettier/prettier`
- `caddyserver/caddy`
- `moment/moment`
- `dotnet/runtime`
- `git/git`
- `puppeteer/puppeteer`
- `django/django`
- `shadcn-ui/ui`
- `rollup/rollup`
- `ohmyzsh/ohmyzsh`
- `storybookjs/storybook`
- `gin-gonic/gin`

## Frozen set (60)
- `eslint/eslint`
- `etcd-io/etcd`
- `angular/angular`
- `JetBrains/kotlin`
- `reduxjs/redux-toolkit`
- `clap-rs/clap`
- `facebook/react-native`
- `remix-run/react-router`
- `elixir-lang/elixir`
- `phoenixframework/phoenix`
- `facebook/react`
- `nginx/nginx`
- `pallets/flask`
- `golang/go`
- `moby/moby`
- `jestjs/jest`
- `BurntSushi/ripgrep`
- `rust-lang/rust`
- `microsoft/vscode`
- `numpy/numpy`
- `koajs/koa`
- `expo/expo`
- `fastapi/fastapi`
- `drizzle-team/drizzle-orm`
- `psf/requests`
- `ziglang/zig`
- `cilium/cilium`
- `spring-projects/spring-boot`
- `kubernetes/kubernetes`
- `vitejs/vite`
- `curl/curl`
- `junegunn/fzf`
- `microsoft/playwright`
- `apache/airflow`
- `php/php-src`
- `axios/axios`
- `encode/starlette`
- `typeorm/typeorm`
- `envoyproxy/envoy`
- `pandas-dev/pandas`
- `ant-design/ant-design`
- `spf13/cobra`
- `redis/redis`
- `babel/babel`
- `jqlang/jq`
- `rails/rails`
- `scikit-learn/scikit-learn`
- `nim-lang/Nim`
- `apache/spark`
- `denoland/deno`
- `pmndrs/zustand`
- `labstack/echo`
- `grafana/grafana`
- `huggingface/transformers`
- `sharkdp/bat`
- `tailwindlabs/tailwindcss`
- `istio/istio`
- `evanw/esbuild`
- `oven-sh/bun`
- `ruby/ruby`
