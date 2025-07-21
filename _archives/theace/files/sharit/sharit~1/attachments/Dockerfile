FROM oven/bun:latest as deps

WORKDIR /app
COPY ./shareIt/*.json /app/

RUN bun install

# Stage 2
FROM oven/bun:latest


RUN adduser dev

RUN apt-get clean && apt-get update


RUN bunx playwright install-deps

COPY ./shareIt /home/dev/

# writeable uploads
RUN mkdir -p /home/dev/uploads && chmod 777 /home/dev/uploads


ARG PLAYWRIGHT_BROWSER_TYPE=firefox
ENV BROWSER=$PLAYWRIGHT_BROWSER_TYPE

ARG PLAYWRIGHT_BROWSERS_PATH=/home/dev/.cache/ms-playwright


# writeable cache
RUN mkdir -p /home/dev/.cache && chmod 777 /home/dev/.cache

USER dev
RUN bunx playwright install $BROWSER
# RUN bunx playwright install

COPY --from=deps /app/node_modules /home/dev/node_modules

WORKDIR /home/dev
CMD ["bun", "run", "start"]