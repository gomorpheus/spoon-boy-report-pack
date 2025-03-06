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

class CypherPasswordAccessReportProvider extends AbstractReportProvider {
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
            repResults = new Sql(dbConnection).rows("SELECT date_created, description  FROM morpheus.audit_log WHERE object_class = 'cypherItem';");
        } finally {
            morpheus.report.releaseDatabaseConnection(dbConnection);
        }

        Observable<GroovyRowResult> observable = Observable.fromIterable(repResults) as Observable<GroovyRowResult>;
        observable.map { resultRow ->
            def Map<String, Object> data = [:];
            data = [
                dateCreated: resultRow.date_created,
                username: resultRow.description.split("suser=")[1].split(" ")[0]
                //objectId: resultRow
            ];

            ReportResultRow resultRowRecord = new ReportResultRow(section: ReportResultRow.SECTION_MAIN, displayOrder: displayOrder++, dataMap: data);
            return resultRowRecord;
        }.buffer(50).doOnComplete {
            morpheus.report.updateReportResultStatus(reportResult, ReportResult.Status.ready).blockingAwait();
        }.doOnError { Throwable t ->
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
