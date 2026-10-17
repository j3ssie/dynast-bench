# The build context with its answer-key comments blanked out
# (dynast-bench/tools/annotations/strip.mjs). Every COPY of app files below
# reads from this stage, never from the raw context.
FROM --platform=$BUILDPLATFORM node:22-bookworm-slim AS dynast-src
COPY --from=dynast-annotations strip.mjs /opt/dynast/strip.mjs
COPY . /src
RUN node /opt/dynast/strip.mjs /src

FROM python:3.12-slim
WORKDIR /partner
COPY --from=dynast-src /src/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY --from=dynast-src /src/ .
EXPOSE 9099
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "9099"]
