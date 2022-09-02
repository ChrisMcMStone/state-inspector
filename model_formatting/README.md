
# Set-up

`python model_formatting/scripts/mypydot/setup.py install`

Modify `scripts/replacements.json` to specify rules for string replacements in model labels. 
Modify `scripts/coloredPaths.json` to specify input sequences to be colored and their corresponding colours.


# Run

Take the `unformatted_full-model.dot` or the `unformatted_minimised-model.dot` from the output directory of your learning tests (support for this has been added as of 25/08/2020).

To run: `./trim_model model.dot [output.dot] [merge_transitions] [convert to graphml]`

The final three parameters are optional. `merge_transitions` and `convert_to_graphml` should be enabled by passing `1` as the parameter
