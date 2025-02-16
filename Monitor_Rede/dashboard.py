import json
from dash import Dash, html, dcc, callback, Output, Input
import plotly.graph_objs as go

# Inicializa o app Dash
app = Dash(__name__)
server = app.server

# Layout do dashboard
app.layout = html.Div([
    html.H1("Dashboard ART-System"),
    dcc.Interval(id="interval-update", interval=3000, n_intervals=0),  # Atualiza a cada 3 segundos
    dcc.Graph(id="pps-graph"),
    html.H2("Anomalias Detectadas"),
    html.Div(id="anomaly-list", style={'whiteSpace': 'pre-line', 'fontFamily': 'monospace'})
])

@callback(
    [Output("pps-graph", "figure"),
     Output("anomaly-list", "children")],
    [Input("interval-update", "n_intervals")]
)
def update_dashboard(n):
    try:
        # Lê os dados do arquivo JSON gerado pelo ART-System
        with open("stats.json", "r") as f:
            stats = json.load(f)
    except Exception as e:
        stats = {"pps_history": [], "anomalies": []}

    pps_data = stats.get("pps_history", [])
    anomalies = stats.get("anomalies", [])

    # Cria o gráfico de pps ao longo do tempo
    figure = {
        "data": [
            go.Scatter(
                x=list(range(len(pps_data))),
                y=pps_data,
                mode="lines+markers",
                name="Packets per Second"
            )
        ],
        "layout": go.Layout(
            title="Packets per Second (PPS)",
            xaxis={"title": "Intervalos"},
            yaxis={"title": "PPS"}
        )
    }

    # Cria uma lista de strings para exibir as anomalias
    anomaly_text = ""
    if anomalies:
        for anomaly in anomalies:
            anomaly_text += f"Tipo: {anomaly.get('type')}, Detalhes: {anomaly}\n"
    else:
        anomaly_text = "Nenhuma anomalia detectada."

    return figure, anomaly_text

if __name__ == '__main__':
    app.run_server(debug=True)