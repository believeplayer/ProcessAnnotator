Put extra rule packs here as *.yaml or *.yml files.
They are loaded after rules/rules.yaml and merged by priority.

Example file: my_rules.yaml

rules:
  - id: example_myapp
    priority: 150
    category: vendor
    annotation: "My custom app"
    annotation_en: "My custom app"
    match:
      name_equals: "MyApp.exe"
