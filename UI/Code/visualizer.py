import dash
from dash import Dash, dcc, html, Input, Output, callback
import dash_ag_grid as dag
from dash import html, Input, Output, State, no_update
from dash import dcc
import pandas as pd
import plotly.express as px
import plotly.graph_objs as go
import sys

try:
    csv_data = sys.argv[1]    
    df = pd.read_csv(csv_data)

except pd.errors.EmptyDataError:
    print('EmptyDataError: No data to parse from file.')

app = dash.Dash(__name__)

grid = dag.AgGrid(
    id='my-ag-grid',
    rowData=df.to_dict('records'),
    # Below is most dynamic option for handling any input columns.
    # However, opting for hardcoding columns names for more granular width control.
    #columnDefs=[{'field':i} for i in df.columns],
    columnDefs=[
        { 'field':'EventTime',    'resizable':True, 'width':180 },
        { 'field':'EventCount',   'resizable':True, 'width':135 },
        { 'field':'Service',      'resizable':True, 'width':150 },
        { 'field':'Name',         'resizable':True, 'width':300 },
        { 'field':'Summary',      'resizable':True, 'width':1337 },
        { 'field':'Url',          'resizable':True, 'width':750 },
        { 'field':'Label',        'resizable':True, 'width':500 },
        { 'field':'IsMapped',     'resizable':True, 'width':135 },
        { 'field':'IsSuppressed', 'resizable':True, 'width':135 },
    ],
    defaultColDef={'resizable':True, 'sortable':True, 'filter':True, 'filter':'agTextColumnFilter'},
    dashGridOptions={'pagination':True, 'paginationPageSize':100, 'rowHeight':30, 'gridOptions':{
            'animateRows':True,
            'rowSelection':'multiple',
        }},
    className='ag-theme-alpine-dark',
    style={'height':'100vh', 'overflowY':'auto'},
) 

# App layout
app.layout = html.Div(
    style={'backgroundColor':'#78cbfa'},
    children= [
    html.Div(style={'display':'flex', 'backgroundColor':'#361292', 'height':'111px', 'alignItems':'center', 'justify-content':'space-between'}, children=[
        html.Div([
            html.Img(
                src=app.get_asset_url('permiso_logo.svg'),
                style={'height':'60px', 'padding':'10px'}
            )
        ]),
        html.Div(style={'margin-right':'10px'}, 
            children=[
                html.Button(
                    'Mapped+Unmapped😎',
                    id='mapped-and-unmapped-btn',
                    n_clicks=0,
                    style={
                        'border':'none',
                        'color':'white',
                        'padding':'15px 32px',
                        'textAlign':'center',
                        'textDecoration':'none',
                        'display':'inline-block',
                        'fontSize':'13px',
                        'margin':'4px 2px',
                        'transitionDuration':'0.4s',
                        'cursor':'pointer',
                        'borderRadius':'12px'
                    },
                ),
                html.Button(
                    'Mapped😀',
                    id='mapped-btn',
                    n_clicks=0,
                    style={
                        'border':'none',
                        'color':'white',
                        'padding':'15px 32px',
                        'textAlign':'center',
                        'textDecoration':'none',
                        'display':'inline-block',
                        'fontSize':'13px',
                        'margin':'4px 2px',
                        'transitionDuration':'0.4s',
                        'cursor':'pointer',
                        'borderRadius':'12px'
                    },
                ),
                html.Button(
                    'Unmapped🙁',
                    id='unmapped-btn',
                    n_clicks=0,
                    style={
                        'border':'none',
                        'color':'white',
                        'padding':'15px 32px',
                        'textAlign':'center',
                        'textDecoration':'none',
                        'display':'inline-block',
                        'fontSize':'13px',
                        'margin':'4px 2px',
                        'transitionDuration':'0.4s',
                        'cursor':'pointer',
                        'borderRadius':'12px'
                    },
                )
            ],
        ),
    ]),
    html.Div(style={'display':'flex', 'justifyContent':'center', 'margin-top':'15px'}, 
        children=[ 
            html.Div([html.Img(
                src=app.get_asset_url('banner.svg'),
                style={'alignSelf':'flex-start', 'height':'290px'}),
                    html.P(
                id='row-count-info',
                style={
                    'color':'white',
                    'text-align':'center',
                    'font-size':'20px',
                    'background-color':'#3498db',
                    'padding':'10px',
                    'border-radius':'5px',
                    'box-shadow':'0px 2px 5px rgba(0, 0, 0, 0.3)'
                }
            )]),
        ]
    ),
    html.Div(style={'display':'flex', 'justify-content':'center'}, 
        children = [
            dcc.Input(
                id='search-input',
                type='text',
                placeholder='Search...',
                style={
                    'fontSize':'20px',
                    'padding':'10px',
                    'backgroundColor':'#3498db',
                    'color':'white',
                    'border':'none',
                    'borderRadius':'5px',
                    'boxShadow':'0px 2px 5px rgba(0, 0, 0, 0.3)',
                    'cursor':'pointer',
                    'transition':'background-color 0.3s',
                    'margin-left':'10px',
                    'width':'700px',
                    'textAlign':'center'
                }
            )
        ]
    ),
    html.Div([html.Span('Copy Selected '), dcc.Clipboard(id='clipboard-state', style={'display':'inline-block', 'margin-top':'10px'}),]),
    html.Div([grid]),
])

@callback(
    Output('clipboard-state', 'content'),
    Input('clipboard-state', 'n_clicks'),
    Input('my-ag-grid', 'columnState'),
    State('my-ag-grid', 'selectedRows'),
    prevent_initial_call=True,
)

def selected(n, col_state, selected):
    if selected is None:
        return 'No selections'
    if col_state is None:
        return no_update

    dff = pd.DataFrame(selected)

    # get current column order in grid
    columns = [row['colId'] for row in col_state]
    dff = dff[columns]

    return dff.to_string()

@app.callback(
    Output('my-ag-grid', 'rowData'),
    Output('row-count-info', 'children'),
    Output('mapped-btn', 'style'),
    Output('unmapped-btn', 'style'),
    Output('mapped-and-unmapped-btn', 'style'),
    Input('mapped-btn', 'n_clicks'),
    Input('unmapped-btn', 'n_clicks'),
    Input('mapped-and-unmapped-btn', 'n_clicks'),
    Input('search-input', 'value'),
    State('my-ag-grid', 'rowData'),
)

def update_grid(mapped_clicks, unmapped_clicks, mapped_and_unmapped_clicks, search_value, current_rows):
    ctx = dash.callback_context
    button_id = ctx.triggered[0]['prop_id'].split('.')[0] if ctx.triggered else None
    # Define a common style dictionary
    common_style = {
        'border':'none',
        'color':'white',
        'padding':'15px 32px',
        'textAlign':'center',
        'textDecoration':'none',
        'display':'inline-block',
        'fontSize':'13px',
        'margin':'4px 2px',
        'transitionDuration':'0.4s',
        'cursor':'pointer',
        'borderRadius':'12px'
    }

    # Adjust the style based on the button click
    if button_id == 'mapped-btn' and mapped_clicks > 0:
        filtered_df = df[df['IsMapped'] == True]
        mapped_style = {'backgroundColor':'#e75036', **common_style}
        unmapped_style = {'backgroundColor':'#67b5d8', **common_style}
        reset_style = {'backgroundColor':'#67b5d8', **common_style}
        total_sum = filtered_df['EventCount'].sum()
        suppressed = filtered_df[filtered_df['IsSuppressed'] == True ]
        row_count = len(filtered_df) - len(suppressed)
        event_or_events = 'event' if total_sum == 1 else 'events'
        click_or_clicks = 'click' if row_count == 1 else 'clicks'
        count_info = f'{total_sum} {event_or_events} -> {row_count} {click_or_clicks}'

    elif button_id == 'unmapped-btn' and unmapped_clicks > 0:
        filtered_df = df[df['IsMapped'] == False]
        mapped_style = {'backgroundColor':'#67b5d8', **common_style}
        unmapped_style = {'backgroundColor':'#e75036', **common_style}
        reset_style = {'backgroundColor':'#67b5d8', **common_style}
        total_sum = filtered_df['EventCount'].sum()
        event_or_events = 'event' if total_sum == 1 else 'events'
        count_info = f'{total_sum} {event_or_events}'

    elif button_id == 'mapped-and-unmapped-btn' and mapped_and_unmapped_clicks > 0:
        filtered_df = df
        mapped_style = {'backgroundColor':'#67b5d8', **common_style}
        unmapped_style = {'backgroundColor':'#67b5d8', **common_style}
        reset_style = {'backgroundColor':'#e75036', **common_style}
        total_sum = filtered_df['EventCount'].sum()
        row_count = len(filtered_df)
        event_or_events = 'event' if total_sum == 1 else 'events'
        row_or_rows = 'row' if row_count == 1 else 'rows'
        count_info = f'{total_sum} {event_or_events} -> {row_count} {row_or_rows}'

    else:
        filtered_df = pd.DataFrame(current_rows) if current_rows else df
        mapped_style = {'backgroundColor':'#67b5d8', **common_style}
        unmapped_style = {'backgroundColor':'#67b5d8', **common_style}
        reset_style = {'backgroundColor':'#e75036', **common_style}
        total_sum = filtered_df['EventCount'].sum()
        row_count = len(filtered_df)
        event_or_events = 'event' if total_sum == 1 else 'events'
        row_or_rows = 'row' if row_count == 1 else 'rows'
        count_info = f'{total_sum} {event_or_events} -> {row_count} {row_or_rows}'

        if search_value:
            try:
                  search_lower = search_value.lower()
                  filtered_df = df[df.apply(lambda row: any(str(item).lower().find(search_lower) != -1 for item in row), axis=1)]
                  if len(filtered_df) <= 0:
                      count_info = 'No results' 
            except Exception as e:
                  print(f'Error filtering DataFrame: {e}')

    return filtered_df.to_dict('records'), count_info, mapped_style, unmapped_style, reset_style

if __name__ == '__main__':
    app.run_server(debug=True)
