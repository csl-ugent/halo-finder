#!/bin/bash
diff <(grep '^%struct' output-interprocedural-dont-count | sort) <(grep '^struct' output-interprocedural-dont-report)
