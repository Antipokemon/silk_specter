PYTHON ?= python3
SCENARIO ?= easy
INDEX ?= asteron_easy_v030
BACKGROUND_EVENTS ?= 5000
ENTERPRISE_BACKGROUND_EVENTS ?= 45000

.PHONY: validate generate generate-easy splunk-load clean-generated status

validate:
	$(PYTHON) -m unittest discover -s tests -v

generate:
	$(PYTHON) generator/generate.py --scenario $(SCENARIO)

generate-easy:
	$(PYTHON) generator/generate.py --scenario easy --output dataset/easy --background-events $(BACKGROUND_EVENTS) --enterprise-background-events $(ENTERPRISE_BACKGROUND_EVENTS)

splunk-load:
	./scripts/load_to_splunk.sh easy $(INDEX)

status:
	@$(PYTHON) scripts/scenario_status.py

clean-generated:
	rm -rf dataset/easy/raw dataset/easy/hec dataset/easy/ingest_manifest.csv
