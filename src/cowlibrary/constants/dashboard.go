package constants

var CowTemplateJinjaReport = `<div class="container pb-5">
<div class="row">
    <div class="col-12 mt-4">
        <div class="card mt-2">
            <div class="card-body">
                <div class="form-row py-3">
                <div class="col-md-12">
                    <div class="header-title">{{ClassName}}</div>
                        {# <div class="col-md-1 icon-container pointer pull-right isMockChart" title="Execute">
                        <input type="checkbox" value="081ca6ba-b8df-4977-a2b6-cbdb654f03bf" class="isMockChart" 
                            checked data-toggle="toggle" data-on="Sample Data" data-off="Real Data" data-offstyle="success" data-height="25">
                    </div> #}
                </div>
                    <div class="col-md-12">
                        <div class="center-chart" id="{{ModuleName}}">{{ embed(roots.{{ModuleName}}) }}</div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>`

var CowTemplateJinja = `{% from macros import embed %}


<div class="main-content-inner" id="mainContent">
    <div class="row">      
        <div class="container pt-4">
            <div class="col-md-6">
                <div class="col-md-6 pull-left __selectedAssesments hidden" hidden>
                    <h4>Selected Assessments: <label class="cow-color"></label></h4>
                </div>
            </div>
            <div class="col-md-1 pull-right pt-3">
                <input type="hidden" id="dashboardPlanId" value="">
                <input type="hidden" id="dashboardId" value="">
                <div class=" icon-container pointer filter-dashboard pull-right" title="">

                    <input type="checkbox" value="" class="checkbox bt-checkbox isMockChart isMockDashboard" 
                        checked data-toggle="toggle" data-on="Sample Data" data-off="Real Data" data-offstyle="success" 
                        data-height="25">
                </div>
            </div>
            <div class="col-md-5 pull-right d-flex hide" id="insightsHistoryDiv">
                <div class="col-md-9 mb-3">
                    <label>Recent filters</label>
                    <select class="form-control" name="insights_history" id="insights_history">
                    <option disabled="disabled" selected="selected">Select a recent filter</option></select>
                </div>
                <div class="col-md-1 pointer pull-right filter-dashboard pt-3 mt-3" title="Dashboard Filter" id="dashboardFilterIcon">
                    <i class="fa fa-filter icon-size-2-5" aria-hidden="true"></i>
                </div>
            </div>

            <div class="col-md-2 pt-3 mt-2 pl-5">
                <div class="icon-container mt-1 downloadInsightsCode">
                    <span class="ti-download bold"></span><span class="icon-name blue bold"> Source Code</span>
                </div>
            </div>
        </div>
    </div>
    
    {# update the charts here #}
        
        
    </div>
</div>

{{ plot_script | indent(8) }}

<script>
var azData = []
{{ js_script | indent(8) }}
$('input.isMockChart[type=checkbox][data-toggle^=toggle]').bootstrapToggle();
</script>`

var CowDashBoardJS = `$(function () {
    var derivers = $.pivotUtilities.derivers;
    $("#pivot_table").pivotUI(azData)
});`
var FilterJinja = `{% from macros import embed %}

<div class="form-row">
    <label>Plans</label>
    <div class="col-md-6 mb-3" id="plans_Dropdown__">{{ embed(roots.plans) }}</div>
</div>
<div class="form-row">
    <label>Plan Instances</label>
    <div class="col-md-6 mb-3" id="date_RangeFilter__">{{ embed(roots.plan_instances) }}</div>
</div>
<div class="form-row">
    <label>Control Status</label>
    <div class="col-md-6 mb-3" id="orderFilter__">{{ embed(roots.control_status) }}</div>
</div>
<div class="form-row">
    <label>Users</label>
    <div class="col-md-6 mb-3" id="limitFilter__">{{ embed(roots.users) }}</div>
</div>

{{ plot_script | indent(8) }}
<script>
{{ js_script | indent(8) }}
</script>`

var MarkDown = `##### AZURE subscription summary`

var SampleDashboard = `from cowreportsengine.cowutils import (
    cowsynthesizerutils,
    cowdictutils,
    cowreportsutils,
)
from cowreportsengine.cowmodels import cowmodels
from compliancecow.models import cowreport
import pandas as pd
import json
import logging

# ADD_IMPORTS_HERE


logger = logging.getLogger("cowreportsengine")


class {{DashboardClassName}}(cowmodels.CowReportsBaseModel):
    def __init__(self, req_obj, *args, **kwargs):
        cowmodels.CowReportsBaseModel.__init__(self, req_obj, *args, **kwargs)

        # INITIATE_REPORTS_HERE

    def WhoAmI(self, *args, **kwargs):
        """Standard method present in all Synthesizer Filters. This will provide the context of the Filter and its outputs to the Synthesizer Orchestrator"""

        return self.filtermetadata

    def GenerateReportDataAsHTMLContent(self, df=pd.DataFrame()):
        """
        This method will produce report data as HTML Content, for the data provided.
        Args :
            df : pd.Dataframe() .this data frame data is used to produce the report.defaults to an empty dataframe.
        Returns:
            cowreport.CowDashboardResult: Result object containing the the generated charts and title.
        """

        plots = self.__get_dashboard_data()

        #uncomment and pass the report module name
        #data = self.reportmodulename.GenerateReportDataAsJSON()

        data = None

        template_variables = {"js_script": self.js_as_text, "data": ""}
        if cowdictutils.isValidKey(data, "data"):
            template_variables["data"] = json.dumps(
                data["data"], default=cowsynthesizerutils.dataframeserializer
            )

        template_variables["plan_id"] = self.plan_id
        template_variables["id"] = self.id

        plots = cowreportsutils.buildresult(
            plot=plots,
            title="Cloud",
            template=self.cow_template,
            template_variables=template_variables,
        )
        return cowreport.CowDashboardResult(
            charts=plots, title="Sample Report"
        )

    def GenerateReportDataAsBokehHTMLObject(self, df=pd.DataFrame()):
        """
        This method will produce report data as Bokeh obj
        """

        charts = {
            # MAP_CHARTS_HERE
        }

        return cowreport.CowDashboardResult(charts=charts)

    def GenerateReportDataAsMDFile(self, df=pd.DataFrame()):
        """
        This method will produce report data as MarkDown file content
        """
        df = self.__get_data__(df)
        newdf = pd.DataFrame()
        data = cowreportsutils.dfToMarkDownStr(newdf, None, self.markdown)

        return cowreport.CowDashboardResult(data=data)

    def GenerateReportDataAsPDFFile(self):
        """
        This method will produce report data as PDF file content
        """
        return None

    def __get_mock_data__(self, df=pd.DataFrame()):
        """
        This method will give dashboard with mockdata,pass your sample data in a dataframe
        """
        self.report_data = df
        return self.report_data

    def __get_dashboard_data(self, is_plot_return_call=True):
        plots = None
        if not is_plot_return_call:
            plots = {
                # MAP_PLOTS_HERE
            }
        else:
            return (
                # ADD_PLOTS
            )

        return plots

    def __get_data__(self, df=pd.DataFrame()):
        # You can define the data which can be used to create dasboard. And also you can export the data through api
        self.report_data = df
        return self.report_data
`

var TemplateJinja = `{% from macros import embed %}

<!DOCTYPE html>
<html lang="en">
{% block head %}

<head>
    {% block inner_head %}
    <meta charset="utf-8">
    <title>{% block title %}{{ title | e if title else "Bokeh Plot" }}{% endblock %}</title>
    {% block preamble %}{% endblock %}
    {% block resources %}
        {% block css_resources %}
            {{ bokeh_css | indent(8) if bokeh_css }}
        {% endblock %}
        {% block js_resources %}
            {{ bokeh_js | indent(8) if bokeh_js }}
        {% endblock %}
    {% endblock %}
    {% block postamble %}{% endblock %}
    {% endblock %}
    <style>
        table {
            font-family: arial, sans-serif;
            border-collapse: collapse;
            width: 100%;
        }

        td,
        th {
            border: 1px solid #dddddd;
            text-align: left;
            padding: 8px;
        }

        th{
            background-color: #4949b759;
        }
    </style>
</head>
{% endblock %}
{% block body %}

<body>
    {% block inner_body %}
        {% block contents %}
            <h1>Successfully Rendered</h1>
             <div>
                <table>
                    <tr>
                        <th>Control Details</th>
                        <th>Report Details</th>
                        <th>Summary of Assesment</th>
                    </tr>
                    <tr>
                        <td colspan="3">Control Objective : Some long text</td>
                    </tr>
                    <tr>
                        <td>{{ control_details.sample | indent(8) }}</td>
                        <td></td>
                        <td>{{ embed(roots.cloud_subscription_report) }}</td>
                    </tr>
                </table>
            </div>
        {% endblock %}
    {{ plot_script | indent(8) }}
    {% endblock %}
</body>
<script>
    function table_to_csv(source) {
    const columns = Object.keys(source.data)
    const nrows = source.get_length()
    const lines = [columns.join(',')]

    for (let i = 0; i < nrows; i++) {
        let row = [];
        for (let j = 0; j < columns.length; j++) {
            const column = columns[j]
            row.push(source.data[column][i].toString())
        }
        lines.push(row.join(','))
    }
    return lines.join('\n').concat('\n')
}


const filename = 'data_result.csv'
const filetext = table_to_csv(source)
const blob = new Blob([filetext], { type: 'text/csv;charset=utf-8;' })

//addresses IE
if (navigator.msSaveBlob) {
    navigator.msSaveBlob(blob, filename)
} else {
    const link = document.createElement('a')
    link.href = URL.createObjectURL(blob)
    link.download = filename
    link.target = '_blank'
    link.style.visibility = 'hidden'
    link.dispatchEvent(new MouseEvent('click'))
}
</script>
{% endblock %}

</html>`

var DashBoardMetaJson = `{
    "tags": [
        "dashboard"
    ],
    "reportsFilters": [
        {
            "name": "DashBoard Name",
            "tags": [],
            "description": "Description",
            "supportedOutputFormats": [
                "md",
                "html",
                "bokeh",
                "json",
                "pdf"
            ]
        }
    ]
}`
