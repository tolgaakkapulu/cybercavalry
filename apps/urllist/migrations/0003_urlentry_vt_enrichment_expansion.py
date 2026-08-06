# Manually authored — extends URLEntry with the additional VirusTotal
# enrichment columns surfaced in the URL tooltip (reputation, community votes,
# HTTP response, redirect count, serving IP, tags, languages, engine
# breakdown, and domain-endpoint-only registrar/creation/popularity fields).

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('urllist', '0002_rename_urllist_ur_is_acti_idx_urllist_url_is_acti_8c179d_idx'),
    ]

    operations = [
        migrations.AddField(
            model_name='urlentry',
            name='vt_reputation',
            field=models.IntegerField(blank=True, null=True,
                                      help_text='Community-driven reputation score; negative = suspicious'),
        ),
        migrations.AddField(
            model_name='urlentry',
            name='vt_votes_harmless',
            field=models.IntegerField(blank=True, null=True,
                                      help_text='Community votes marking the URL/domain harmless'),
        ),
        migrations.AddField(
            model_name='urlentry',
            name='vt_votes_malicious',
            field=models.IntegerField(blank=True, null=True,
                                      help_text='Community votes marking the URL/domain malicious'),
        ),
        migrations.AddField(
            model_name='urlentry',
            name='vt_http_code',
            field=models.IntegerField(blank=True, null=True,
                                      help_text='Last HTTP response code observed by VT (URL endpoint only)'),
        ),
        migrations.AddField(
            model_name='urlentry',
            name='vt_content_length',
            field=models.BigIntegerField(blank=True, null=True,
                                         help_text='Response body size (bytes) from the last VT crawl'),
        ),
        migrations.AddField(
            model_name='urlentry',
            name='vt_redirect_count',
            field=models.IntegerField(blank=True, null=True,
                                      help_text='Number of redirects in the redirection_chain'),
        ),
        migrations.AddField(
            model_name='urlentry',
            name='vt_serving_ip',
            field=models.CharField(blank=True, default='', max_length=45,
                                   help_text='IP that served the URL during the last VT crawl'),
        ),
        migrations.AddField(
            model_name='urlentry',
            name='vt_tags',
            field=models.CharField(blank=True, default='', max_length=255,
                                   help_text='Comma-joined VT-provided tags (e.g. suspicious-tld, malware)'),
        ),
        migrations.AddField(
            model_name='urlentry',
            name='vt_languages',
            field=models.CharField(blank=True, default='', max_length=255,
                                   help_text='Comma-joined page languages detected by VT'),
        ),
        migrations.AddField(
            model_name='urlentry',
            name='vt_harmless',
            field=models.IntegerField(blank=True, null=True,
                                      help_text='Engines that voted harmless in the last analysis'),
        ),
        migrations.AddField(
            model_name='urlentry',
            name='vt_suspicious',
            field=models.IntegerField(blank=True, null=True,
                                      help_text='Engines that voted suspicious in the last analysis'),
        ),
        migrations.AddField(
            model_name='urlentry',
            name='vt_undetected',
            field=models.IntegerField(blank=True, null=True,
                                      help_text='Engines that returned undetected in the last analysis'),
        ),
        migrations.AddField(
            model_name='urlentry',
            name='vt_registrar',
            field=models.CharField(blank=True, default='', max_length=255,
                                   help_text='Domain registrar from whois (domain endpoint only)'),
        ),
        migrations.AddField(
            model_name='urlentry',
            name='vt_creation_date',
            field=models.DateTimeField(blank=True, null=True,
                                       help_text='Domain creation date from whois'),
        ),
        migrations.AddField(
            model_name='urlentry',
            name='vt_popularity_rank',
            field=models.IntegerField(blank=True, null=True,
                                      help_text='Best (lowest) popularity rank across VT sources (Cisco/Alexa/etc.)'),
        ),
    ]
