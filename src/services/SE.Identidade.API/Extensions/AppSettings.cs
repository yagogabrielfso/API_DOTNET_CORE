namespace SE.Identidade.API.Extensions
{
    public class AppSettings
    {

        public string? Secret { get; set; } // Chave
        public int? ExpiracaoHoras { get; set; } // Quanto tempo esse token vai ser valido em horas
        public string? Emissor { get; set; }     // Quem é o emissor
        public string? ValidoEm { get; set; }    // Onde é valido(audiência)

    }
}
