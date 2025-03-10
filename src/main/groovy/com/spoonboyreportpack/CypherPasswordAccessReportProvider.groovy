package com.spoonboyreportpack;

import com.morpheusdata.core.AbstractReportProvider;
import com.morpheusdata.core.MorpheusContext;
import com.morpheusdata.core.Plugin;
import com.morpheusdata.model.OptionType;
import com.morpheusdata.model.ReportResult;
import com.morpheusdata.model.ReportResultRow;
import com.morpheusdata.response.ServiceResponse;
import com.morpheusdata.views.HTMLResponse;
import com.morpheusdata.views.ViewModel;

import groovy.sql.GroovyRowResult;
import groovy.sql.Sql;
import java.sql.Connection;
import io.reactivex.rxjava3.core.Observable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.time.format.DateTimeFormatter;

class CypherPasswordAccessReportProvider extends AbstractReportProvider {
    private static final Logger log = LoggerFactory.getLogger(CypherPasswordAccessReportProvider.class);
    private static final DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    protected MorpheusContext morpheusContext;
    protected Plugin plugin;

    CypherPasswordAccessReportProvider(Plugin plugin, MorpheusContext morpheusContext) {
        this.morpheusContext = morpheusContext;
        this.plugin = plugin;
    }

    @Override
    MorpheusContext getMorpheus() {
        return this.morpheusContext;
    }

    @Override
    Plugin getPlugin() {
        return this.plugin;
    }

    @Override
    String getCode() {
        return "spoon-boy-cypher-password-access-report";
    }

    @Override
    String getName() {
        return "Cypher Password Access";
    }

    @Override
    ServiceResponse validateOptions(Map opts) {
        return ServiceResponse.success();
    }

    @Override
    void process(ReportResult reportResult) {
        morpheus.report.updateReportResultStatus(reportResult, ReportResult.Status.generating).blockingAwait();
        Long displayOrder = 0;
        List<GroovyRowResult> repResults = [];

        Connection dbConnection;

        try {
            dbConnection = morpheus.report.getReadOnlyDatabaseConnection().blockingGet();
            def sql = new Sql(dbConnection);
            repResults = sql.rows("""
                  SELECT
    a.object_id,
    a.date_created,
    a.description,
    c.item_key,
    CASE
        WHEN locate("suser=", a.description) > 0 THEN SUBSTRING(a.description, locate("suser=", a.description) + 6, locate(' ', a.description, locate("suser=", a.description) + 6) - (locate("suser=", a.description) + 6))
        ELSE ''
    END AS username,
    SUBSTRING(substring(a.description, (locate("cn2=", a.description, 20) + 4),
    ((locate("fullName", a.description, 20) - 4) - (locate("cn2=", a.description, 20) + 4))), 1, LOCATE(' ', substring(a.description, (locate("cn2=", a.description, 20) + 4),
    ((locate("fullName", a.description, 20) - 4) - (locate("cn2=", a.description, 20) + 4))))-1) AS account_id
FROM
    morpheus.audit_log a
LEFT JOIN
    morpheus.cypher_item c ON a.object_id = c.id
WHERE
    a.object_class = 'cypherItem'
    AND substring(a.description, (locate("cn2=", a.description, 20) + 4),
    ((locate("fullName", a.description, 20) - 4) - (locate("cn2=", a.description, 20) + 4))) LIKE concat(${reportResult.getAccount().getId()}, '%')
            """);
            log.info("Fetched {} rows from the database", repResults.size());
            
        } catch (Exception e) {
            log.error("Error fetching data from the database", e);
        } finally {
            morpheus.report.releaseDatabaseConnection(dbConnection);
        }

        Observable<GroovyRowResult> observable = Observable.fromIterable(repResults) as Observable<GroovyRowResult>;
        observable.map { resultRow ->
            def Map<String, Object> data = [:];
            data = [
                dateAccessed: resultRow.date_created.format(formatter),
                username: resultRow.username,
                cypher: resultRow.item_key,
                description: resultRow.description.split(/\|/)[5],
                //accountid: resultRow.account_id
                
            ];
            log.info("Processed row: {}", data);

            ReportResultRow resultRowRecord = new ReportResultRow(section: ReportResultRow.SECTION_MAIN, displayOrder: displayOrder++, dataMap: data);
            return resultRowRecord;
        }.buffer(50).doOnComplete {
            morpheus.report.updateReportResultStatus(reportResult, ReportResult.Status.ready).blockingAwait();
        }.doOnError { Throwable t ->
            log.error("Error processing report", t);
            morpheus.report.updateReportResultStatus(reportResult, ReportResult.Status.failed).blockingAwait();
        }.subscribe { resultRows ->
            morpheus.report.appendResultRows(reportResult, resultRows).blockingGet();
        };
    }

    @Override
    String getDescription() {
        return "Provides a list of access to cypher passwords";
    }

    @Override
    String getCategory() {
        return "security";
    }

    @Override
    Boolean getOwnerOnly() {
        return false;
    }

    @Override
    Boolean getMasterOnly() {
        return false;
    }

    @Override
    Boolean getSupportsAllZoneTypes() {
        return true;
    }

    @Override
    List<OptionType> getOptionTypes() {
        return null;
    }

    @Override
    HTMLResponse renderTemplate(ReportResult reportResult, Map<String, List<ReportResultRow>> reportRowsBySection) {
        ViewModel<Map<String, List<ReportResultRow>>> model = new ViewModel<>();
        model.object = reportRowsBySection;
        return getRenderer().renderTemplate("hbs/cypherPasswordAccessReport", model);
    }
}
