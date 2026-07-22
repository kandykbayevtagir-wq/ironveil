# HTML report and local UI

The HTML reporter creates one portable file with embedded styles and scripts. It does not load a
CDN, font, image, analytics endpoint, or other remote resource. Repository-controlled text is
escaped before rendering and a restrictive Content Security Policy limits active content.

## Generate a report

```console
ironveil scan . --format html --output ironveil-report.html
```

Open the file directly in a browser, or use the local UI:

```console
ironveil ui .
ironveil ui . --no-open --port 8765
ironveil ui . --history
ironveil ui . --diff origin/main...HEAD
```

The server binds only to `127.0.0.1`. The configuration validator rejects another host. No source
or report content is sent to a service, and the server should be stopped when review is complete.

## Report contents

The report contains aggregate severity and category counts, Git branch and commit metadata,
new/baseline/suppressed state, scanned-file and byte statistics, dependency and history status,
and filterable finding cards with masked evidence and remediation. Filters operate entirely in
the browser. Light and dark presentation follow the operating-system preference.

The displayed security score starts at 100 and subtracts 25 for each critical finding, 10 for
high, 5 for medium, 2 for low, and 0 for info, with a floor of zero. Active baseline findings
remain deductions because they are unresolved; suppressed findings are excluded. The report
shows the calculation. This is a prioritization aid, not a probability or certification. Do not
compare scores across materially different scan scopes, rule packs, or confidence thresholds.

The report's Content Security Policy uses exact SHA-256 hashes for its embedded CSS and
JavaScript and otherwise sets `default-src 'none'`. Images are limited to `data:` and fonts,
connections, objects, base URIs, forms, and frames are disabled.

## Handling reports safely

Masking protects complete matched values, but a report still reveals repository paths, line
locations, rule types, Git metadata, and security posture. Store it like a security assessment:

- keep CI artifact retention short;
- restrict access to the repository and workflow run;
- do not attach it to a public issue without reviewing every field;
- delete local copies when they are no longer needed;
- regenerate after a credential has been rotated and the repository remediated.

The GitHub Action Job Summary deliberately contains fewer details than the HTML artifact.
