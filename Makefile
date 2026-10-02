PYTHON ?= python3
SCENARIO ?= easy
INDEX ?= asteron_$(SCENARIO)_v001
NOTABLE_INDEX ?= notable
BACKGROUND_EVENTS ?=
ENTERPRISE_BACKGROUND_EVENTS ?=

BACKGROUND_OVERRIDE = $(if $(strip $(BACKGROUND_EVENTS)),--background-events $(BACKGROUND_EVENTS),)
ENTERPRISE_BACKGROUND_OVERRIDE = $(if $(strip $(ENTERPRISE_BACKGROUND_EVENTS)),--enterprise-background-events $(ENTERPRISE_BACKGROUND_EVENTS),)
AUTHORING_FLAG = $(if $(filter $(SCENARIO),medium hard),--allow-authoring,)

.PHONY: validate status generate generate-easy generate-medium generate-hard generate-all splunk-load splunk-notables clean-generated

validate:
	$(PYTHON) -m unittest discover -s tests -v

status:
	@$(PYTHON) scripts/scenario_status.py

generate:
	$(PYTHON) generator/generate.py --scenario $(SCENARIO) --output dataset/$(SCENARIO) $(AUTHORING_FLAG) $(BACKGROUND_OVERRIDE) $(ENTERPRISE_BACKGROUND_OVERRIDE)

generate-easy:
	$(PYTHON) generator/generate.py --scenario easy --output dataset/easy $(BACKGROUND_OVERRIDE) $(ENTERPRISE_BACKGROUND_OVERRIDE)

generate-medium:
	$(PYTHON) generator/generate.py --scenario medium --allow-authoring --output dataset/medium $(BACKGROUND_OVERRIDE) $(ENTERPRISE_BACKGROUND_OVERRIDE)

generate-hard:
	$(PYTHON) generator/generate.py --scenario hard --allow-authoring --output dataset/hard $(BACKGROUND_OVERRIDE) $(ENTERPRISE_BACKGROUND_OVERRIDE)

generate-all:
	$(MAKE) generate-easy
	$(MAKE) generate-medium
	$(MAKE) generate-hard

splunk-load:
	ALLOW_AUTHORING=1 ./scripts/load_to_splunk.sh $(SCENARIO) $(INDEX)

splunk-notables:
	./scripts/load_notables.sh $(SCENARIO) $(INDEX) $(NOTABLE_INDEX)

clean-generated:
	rm -rf dataset/$(SCENARIO)/raw dataset/$(SCENARIO)/hec dataset/$(SCENARIO)/notables
	rm -f dataset/$(SCENARIO)/ingest_manifest.csv dataset/$(SCENARIO)/manifest.json dataset/$(SCENARIO)/expected_counts.csv
