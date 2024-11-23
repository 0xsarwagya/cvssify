import { humanizeBaseMetric, humanizeBaseMetricValue } from "./humanizer.ts";
import {
	type BaseMetric,
	type EnvironmentalMetric,
	type Metric,
	type MetricValue,
	type Metrics,
	type TemporalMetric,
	baseMetricValues,
	baseMetrics,
	environmentalMetricValues,
	environmentalMetrics,
	temporalMetricValues,
	temporalMetrics,
} from "./models.ts";
import { parseMetricsAsMap, parseVector, parseVersion } from "./parser.ts";

export const validateVersion = (versionStr: string | undefined): void => {
	if (!versionStr) {
		throw new Error(
			"Invalid CVSS string. Example: CVSS:3.0/AV:A/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:L",
		);
	}

	if (versionStr !== "3.0" && versionStr !== "3.1") {
		throw new Error(
			`Unsupported CVSS version: ${versionStr}. Only 3.0 and 3.1 are supported`,
		);
	}
};

const validateVector = (vectorStr: string | null): void => {
	if (!vectorStr || vectorStr.includes("//")) {
		throw new Error(
			"Invalid CVSS string. Example: CVSS:3.0/AV:A/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:L",
		);
	}
};

const checkUnknownMetrics = (
	metricsMap: Map<string, string>,
	knownMetrics?: Metrics,
): void => {
	const allKnownMetrics = knownMetrics || [
		...baseMetrics,
		...temporalMetrics,
		...environmentalMetrics,
	];

	// [...metricsMap.keys()].forEach((userMetric: string) => {
	// 	if (!allKnownMetrics.includes(userMetric as Metric)) {
	// 		throw new Error(
	// 			`Unknown CVSS metric "${userMetric}". Allowed metrics: ${allKnownMetrics.join(
	// 				", ",
	// 			)}`,
	// 		);
	// 	}
	// });
	const keys = [...metricsMap.keys()];

	for (const userMetric of keys) {
		if (!allKnownMetrics.includes(userMetric as Metric)) {
			throw new Error(
				`Unknown CVSS metric "${userMetric}". Allowed metrics: ${allKnownMetrics.join(
					", ",
				)}`,
			);
		}
	}
};

const checkMandatoryMetrics = (
	metricsMap: Map<string, string>,
	metrics: readonly BaseMetric[] = baseMetrics,
): void => {
	// metrics.forEach((metric: Metric) => {
	// 	if (!metricsMap.has(metric)) {
	// 		// eslint-disable-next-line max-len
	// 		throw new Error(
	// 			`Missing mandatory CVSS metric ${metrics} (${humanizeBaseMetric(
	// 				metric,
	// 			)})`,
	// 		);
	// 	}
	// });
	for (const metric of metrics) {
		if (!metricsMap.has(metric)) {
			throw new Error(
				`Missing mandatory CVSS metric ${metrics} (${humanizeBaseMetric(
					metric,
				)})`,
			);
		}
	}
};

const checkMetricsValues = (
	metricsMap: Map<string, string>,
	metrics: Metrics,
	metricsValues: Record<Metric, MetricValue[]>,
): void => {
	for (const metric of metrics) {
		const userValue = metricsMap.get(metric);
		if (!userValue) {
			continue;
		}
		if (!metricsValues[metric].includes(userValue as MetricValue)) {
			const allowedValuesHumanized = metricsValues[metric]
				.map(
					(value: MetricValue) =>
						`${value} (${humanizeBaseMetricValue(value, metric)})`,
				)
				.join(", ");
			throw new Error(
				`Invalid value for CVSS metric ${metric} (${humanizeBaseMetric(
					metric,
				)})${
					userValue ? `: ${userValue}` : ""
				}. Allowed values: ${allowedValuesHumanized}`,
			);
		}
	}
};

export type ValidationResult = {
	isTemporal: boolean;
	isEnvironmental: boolean;
	metricsMap: Map<Metric, MetricValue>;
	versionStr: string | undefined;
};

export const validate = (cvssStr: string): ValidationResult => {
	if (!cvssStr?.startsWith("CVSS:")) {
		throw new Error('CVSS vector must start with "CVSS:"');
	}
	const allKnownMetrics = [
		...baseMetrics,
		...temporalMetrics,
		...environmentalMetrics,
	];
	const allKnownMetricsValues = {
		...baseMetricValues,
		...temporalMetricValues,
		...environmentalMetricValues,
	};

	const versionStr = parseVersion(cvssStr);
	validateVersion(versionStr);

	const vectorStr = parseVector(cvssStr);

	if (!vectorStr) {
		throw new Error(
			"Invalid CVSS string. Example: CVSS:3.0/AV:A/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:L",
		);
	}

	validateVector(vectorStr);

	const metricsMap = parseMetricsAsMap(cvssStr);
	checkMandatoryMetrics(metricsMap);
	checkUnknownMetrics(metricsMap, allKnownMetrics);
	checkMetricsValues(metricsMap, allKnownMetrics, allKnownMetricsValues);

	const isTemporal = [...metricsMap.keys()].some((metric) =>
		temporalMetrics.includes(metric as TemporalMetric),
	);
	const isEnvironmental = [...metricsMap.keys()].some((metric) =>
		environmentalMetrics.includes(metric as EnvironmentalMetric),
	);

	return {
		metricsMap,
		isTemporal,
		isEnvironmental,
		versionStr,
	};
};
