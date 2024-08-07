package constants

var PieChartPY = `from cowreportsengine.cowutils import cowdictutils, cowreportsutils
from cowreportsengine.cowmodels import cowmodels
from compliancecow.models import cowlib, cowreport
import pandas as pd

from math import pi
from bokeh.palettes import Category20c
from bokeh.plotting import figure
from bokeh.transform import cumsum
from bokeh.embed import json_item
from bokeh.models import ColumnDataSource
import logging

logger = logging.getLogger("cowreportsengine")


class {{ClassName}}(cowmodels.CowReportsBaseModel):
    def __init__(self, req_obj, *args, **kwargs):
        cowmodels.CowReportsBaseModel.__init__(
            self, req_obj, *args, **kwargs)
        self.GetData()

    def WhoAmI(self, *args, **kwargs):
        ''' Standard method present in all Synthesizer Filters. This will provide the context of the Filter and its outputs to the Synthesizer Orchestrator'''

        return self.filtermetadata

    def GenerateReportDataAsHTMLContent(self, df=pd.DataFrame()):
        '''
        This method will produce report data as HTML Content
        '''

        return cowreport.CowDashboardResult(widgets=None, charts=None)

    def GenerateReportDataAsBokehHTMLObject(self, df=pd.DataFrame()):
        '''
        This method will produce report data as Bokeh obj
        '''

        charts = {
            "{{ModuleName}}": self.dashboard_chart(),
        }

        return cowreport.CowDashboardResult(charts=charts)

    def GenerateReportDataAsMDFile(self, df=pd.DataFrame()):
        '''
        This method will produce report data as MarkDown file content
        '''
        newdf = pd.DataFrame()

        data = cowreportsutils.dfToMarkDownStr(newdf, None, self.markdown)

        return cowreport.CowDashboardResult(data=data)

    def GenerateReportDataAsPDFFile(self):
        '''
        This method will produce report data as PDF file content
        '''
        return None

    def __get_mock_data__(self, df=pd.DataFrame()):
        #pass your sample data here and modify as per your need
        data = df
        return data
        
    def __get_data__(self, df=pd.DataFrame()):
        client = cowlib.Client(auth_token=self.auth_token)
        controls = []
        if self.assessment_run_ids:
            plan_instances = None
            plans, error = client.get_plans(name="#Assessment Name")
            if error:
                return self.report_data
            if plans == None:
                return self.report_data
            plan_instances, error = client.get_plan_instances(
                ids=[self.assessment_run_ids]
            )
            if error:
                return self.report_data
            if not plan_instances:
                return self.report_data
            plan_instance = plan_instances[0]
            controls = plan_instance.get_plan_instance_controls(having_evidences=True)
        data = self.get_evidence_data_from_controls(
            client, controls, "#Evidence Name"
            )

        return data

    def get_evidence_data_from_controls(
        self, client, controls, fileName
        ) -> pd.DataFrame:
        data = pd.DataFrame()
        for control in controls:
            for evidence in control.evidences:
                if evidence and evidence.file_name and evidence.file_name == fileName:
                    result, error = client.get_evidence_data(evidence)
                    if error:
                        break
                    data = pd.concat([data, result])
                    break
        return data

    def dashboard_chart(self, is_plot_return_call=False):
        df = self.report_data.copy()
        p = figure()
        # make sure p."name" and embed(roots."name") in report dashboard cow_template.jinja file are the same

        title = "Pie Chart"
        tooltip = "@name: @value"

        # Dummy data for the pie chart
        data = {
            'name': ['Category A', 'Category B', 'Category C'],
            'value': [30, 40, 50]
        }

        source = ColumnDataSource(data)

        p = figure(height=250, title=title, toolbar_location=None,
               tools="hover", tooltips=tooltip)

        p.name = "{{ModuleName}}"

        p.wedge(x=0, y=1, radius=0.4, start_angle=0, end_angle='value',
            line_color='white', fill_color='#c9d9d3', legend_field='name', source=source)

        p.axis.visible = False
        p.outline_line_color = None
        p.legend.location = "top_left"
        p.legend.orientation = "horizontal"

        if is_plot_return_call:
            return p

        return json_item(p)
`
var BarChartPY = `from cowreportsengine.cowutils import cowdictutils, cowreportsutils
from cowreportsengine.cowmodels import cowmodels
from compliancecow.models import cowlib, cowreport
import pandas as pd

from math import pi
from bokeh.palettes import Category20c, Category10_6
from bokeh.plotting import figure
from bokeh.transform import cumsum
from bokeh.embed import json_item
from bokeh.models import ColumnDataSource
import logging

logger = logging.getLogger("cowreportsengine")


class {{ClassName}}(cowmodels.CowReportsBaseModel):
    def __init__(self, req_obj, *args, **kwargs):
        cowmodels.CowReportsBaseModel.__init__(
            self, req_obj, *args, **kwargs)
        self.GetData()

    def WhoAmI(self, *args, **kwargs):
        ''' Standard method present in all Synthesizer Filters. This will provide the context of the Filter and its outputs to the Synthesizer Orchestrator'''

        return self.filtermetadata

    def GenerateReportDataAsHTMLContent(self, df=pd.DataFrame()):
        '''
        This method will produce report data as HTML Content
        '''

        return cowreport.CowDashboardResult(widgets=None, charts=None)

    def GenerateReportDataAsBokehHTMLObject(self, df=pd.DataFrame()):
        '''
        This method will produce report data as Bokeh obj
        '''

        charts = {
            "{{ModuleName}}": self.dashboard_chart(),
        }

        return cowreport.CowDashboardResult(charts=charts)

    def GenerateReportDataAsMDFile(self, df=pd.DataFrame()):
        '''
        This method will produce report data as MarkDown file content
        '''
        newdf = pd.DataFrame()

        data = cowreportsutils.dfToMarkDownStr(newdf, None, self.markdown)

        return cowreport.CowDashboardResult(data=data)

    def GenerateReportDataAsPDFFile(self):
        '''
        This method will produce report data as PDF file content
        '''
        return None

    def __get_mock_data__(self, df=pd.DataFrame()):
        #pass your sample data here and modify as per your need
        data = df
        return data

    def __get_data__(self, df=pd.DataFrame()):
        client = cowlib.Client(auth_token=self.auth_token)
        controls = []
        if self.assessment_run_ids:
            plan_instances = None
            plans, error = client.get_plans(name="#Assessment Name")
            if error:
                return self.report_data
            if plans == None:
                return self.report_data
            plan_instances, error = client.get_plan_instances(
                ids=[self.assessment_run_ids]
            )
            if error:
                return self.report_data
            if not plan_instances:
                return self.report_data
            plan_instance = plan_instances[0]
            controls = plan_instance.get_plan_instance_controls(having_evidences=True)
        data = self.get_evidence_data_from_controls(
            client, controls, "#Evidence Name"
            )

        return data

    def get_evidence_data_from_controls(
        self, client, controls, fileName
        ) -> pd.DataFrame:
        data = pd.DataFrame()
        for control in controls:
            for evidence in control.evidences:
                if evidence and evidence.file_name and evidence.file_name == fileName:
                    result, error = client.get_evidence_data(evidence)
                    if error:
                        break
                    data = pd.concat([data, result])
                    break
        return data

    def dashboard_chart(self, is_plot_return_call=False):
        df = self.report_data.copy()
        p = figure()
        # make sure p."name" and embed(roots."name") in report dashboard cow_template.jinja file are same
        
        title = "Bar Chart"
        tooltip = "@x: @$name"

        fruits = ["Apples", "Pears", "Nectarines", "Plums", "Grapes", "Strawberries"]
        counts = [5, 3, 4, 2, 4, 6]

        p = figure(x_range=fruits, y_range=(0, 9), height=350, title="Fruit Counts", toolbar_location=None, tools="")

        p.name = "{{ModuleName}}"

        source = ColumnDataSource(data=dict(fruits=fruits, counts=counts, color=Category10_6))

        p.vbar(x="fruits", top="counts", width=0.9, color="color", legend_field="fruits", source=source)

        p.xgrid.grid_line_color = None
        p.legend.orientation = "horizontal"
        p.legend.location = "top_center"

        if is_plot_return_call:
            return p

        return json_item(p)
`
var DefaultReportPY = `from cowreportsengine.cowutils import (
    cowreportsutils,
)
import concurrent.futures

from cowreportsengine.cowmodels import cowmodels
from compliancecow.models import cowlib, cowreport
import pandas as pd
from bokeh.models import Legend
from math import pi
from bokeh.plotting import figure
from bokeh.transform import cumsum
from bokeh.embed import json_item
from bokeh.palettes import Category20
import logging

logger = logging.getLogger("cowreportsengine")


class {{ClassName}}(cowmodels.CowReportsBaseModel):
    def __init__(self, req_obj, *args, **kwargs):
        cowmodels.CowReportsBaseModel.__init__(self, req_obj, *args, **kwargs)
        self.GetData()

    def WhoAmI(self, *args, **kwargs):
        """Standard method present in all Synthesizer Filters. This will provide the context of the Filter and its outputs to the Synthesizer Orchestrator"""

        return self.filtermetadata

    def GenerateReportDataAsHTMLContent(self, df=pd.DataFrame()):
        """
        This method will produce report data as HTML Content
        """

        return cowreport.CowDashboardResult()

    def GenerateReportDataAsBokehHTMLObject(self, df=pd.DataFrame()):
        """
        This method will produce report data as Bokeh obj
        """

        charts = {
            "{{ModuleName}}": self.dashboard_chart(),
        }
        return cowreport.CowDashboardResult(charts=charts)

    def GenerateReportDataAsMDFile(self, df=pd.DataFrame()):
        """
        This method will produce report data as MarkDown file content
        """

        newdf = pd.DataFrame()

        data = cowreportsutils.dfToMarkDownStr(newdf, None, self.markdown)
        return cowreport.CowDashboardResult(data=data)

    def GenerateReportDataAsPDFFile(self):
        """
        This method will produce report data as PDF file content
        """
        return None
    
    
    def __get_mock_data__(self, df=pd.DataFrame()):
        #pass your sample data here and modify as per your need
        data = df
        return data

    def __get_data__(self, df=pd.DataFrame()):
        client = cowlib.Client(auth_token=self.auth_token)
        controls = []
        if self.assessment_run_ids:
            plan_instances = None
            plans, error = client.get_plans(name="#Assessment Name")
            if error:
                return self.report_data
            if plans == None:
                return self.report_data
            plan_instances, error = client.get_plan_instances(ids=[self.assessment_run_ids])
            if error:
                return self.report_data
            if not plan_instances:
                return self.report_data
            plan_instance = plan_instances[0]
            controls = plan_instance.get_plan_instance_controls(having_evidences=True)
        data = self.get_evidence_data_from_controls(client, controls, "#EvidenceName")

        return data

    def get_evidence_data_from_controls(self, client, controls, fileName) -> pd.DataFrame:
        data = pd.DataFrame()
        for control in controls:
            for evidence in control.evidences:
                if evidence and evidence.file_name and evidence.file_name == fileName:
                    result, error = client.get_evidence_data(evidence)
                    if error:
                        break
                    data = pd.concat([data, result])
                    break
        return data

    def dashboard_chart(self, is_plot_return_call=False):
        df = self.report_data
        p = figure()
        # make sure p."name" and embed(roots."name") in report dashboard cow_template.jinja file are same
        p.name = "{{ModuleName}}"
        #Chart Implementation Goes Here
        if is_plot_return_call:
            return p
        return json_item(p)
`
var ReportCowTemplateJinja = `{% from macros import embed %}

<div id="left" class="col-md-8 cow-content">
    <div class="grid-col max-content-div">
        <div class="card mb-1">
            <div class="card-body" id="planExecutions_chart__">{{ embed(roots.plan_executions) }}</div>
        </div>
    </div>
</div>

{{ plot_script | indent(8) }}`

var ReportMarkDown = `##### Sample report
`
var ReportMetaJson = `{
    "tags": [
        "report"
    ],
    "reportsFilters": [
        {
            "name": "Report Name",
            "tags": [],
            "description": "Report Description",
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
