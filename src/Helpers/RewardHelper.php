<?php

namespace InsuranceCore\Helpers\Helpers;

use App\Helpers\Helpers;
use App\Models\CustomerPolicyModel;
use App\Models\GridRule;
use App\Models\HealthPolicy;
use App\Models\HealthQuote;
use App\Models\HealthRule;
use App\Models\InsuranceProvider;
use App\Models\Leads;
use App\Models\RewardPoint;
use App\Models\Rto;
use App\Models\StateNew;
use Carbon\Carbon;
use Exception;
use Log;
use Throwable;
/**
 * RewardHelper
 *
 * This helper depends on several models and possibly other helpers from the main app.
 * Ensure all dependencies are available and properly imported in your Laravel application.
 */
class RewardHelper
{
    public static function checkRewardPoints(
        $lead,
        $providerId,
        $odPremium = 0,
        $tpPremium = 0,
        $netPremium = 0
    ) {
        try
        {
            $outOdComm = 0;
            $outTpComm = 0;
            $outNetComm = 0;
            $rewardPoints = 0;

            if ( $lead->quote_type == "motor" )
            {
                $vehicleAge = 0;
                $case = $lead->policy_case;
                $bussinessType = "";
                if ( $case == "new" )
                {
                    $bussinessType = "New Business";
                } else
                {
                    $bussinessType = "Rollover";
                }
                if ( $bussinessType )
                {
                    if ( $bussinessType == "Rollover" )
                    {
                        if ( isset ( $lead->registration_date ) )
                        {
                            $regDate = $lead->registration_date;
                            $regDate = Carbon::parse ( $regDate );
                            $currentDate = Carbon::now ();
                            $age = $currentDate->diffInYears ( $regDate );
                            $vehicleAge = $age . " Year";
                        }
                    }
                }
                $vehicleType = "";
                if ( $lead->vehicle_type == "bike" )
                {
                    $vehicleType = "2 Wheeler";
                } elseif ( $lead->vehicle_type == "car" )
                {
                    $vehicleType = "4 Wheeler";
                } elseif ( $lead->vehicle_type == "pcv" )
                {
                    $vehicleType = "Commercial PCV";
                } elseif ( $lead->vehicle_type == "gcv" )
                {
                    $vehicleType = "Commercial GCV";
                } elseif ( $lead->vehicle_type == "mcv" )
                {
                    $vehicleType = "Misc D";
                }

                $modelId = $lead->model_id;

                $rto = Rto::select ( "id", "rtoCode", "state" )
                    ->where ( "rtoCode", $lead->rto_code )
                    ->first ();
                $state = StateNew::select ( "id", "state_name" )
                    ->where ( "state_name", $rto->state )
                    ->first ();

                $getMmv = self::getMmvById ( $lead->object_id );

                $vehicleBody =
                    isset ( $getMmv ) &&
                    isset ( $getMmv[ "data" ] ) &&
                    isset ( $getMmv[ "data" ][ "body_type" ] )
                    ? $getMmv[ "data" ][ "body_type" ]
                    : "";
                $vehicle =
                    isset ( $getMmv ) &&
                    isset ( $getMmv[ "data" ] ) &&
                    isset ( $getMmv[ "data" ][ "vehicle_type" ] )
                    ? $getMmv[ "data" ][ "vehicle_type" ]
                    : "";
                $fuelType =
                    isset ( $getMmv ) &&
                    isset ( $getMmv[ "data" ] ) &&
                    isset ( $getMmv[ "data" ][ "fuel_type" ] )
                    ? $getMmv[ "data" ][ "fuel_type" ]
                    : "";

                $vehicleCategory = Helpers::getVehicleCategory (
                    $vehicleType,
                    $vehicleBody,
                    $vehicle,
                    $fuelType
                );

                $data[ "agent_id" ] = $lead->agent_id;
                $data[ "ncb" ] = $lead->previous_no_claim_bonus;
                // $data['pa'] = $request->pa;
                // $data["slab"] = $slab;
                $data[ "provider" ] = $providerId ?? null;
                $data[ "vehicle_type" ] = $vehicleType;
                $data[ "vehicle_category" ] = $vehicleCategory;
                $data[ "vehicle_age" ] = $vehicleAge;
                $data[ "make_id" ] = (string) $lead->make_id;
                // $data['model_id'] = (string)$modelId;
                $data[ "state_id" ] = (string) $state->id;
                $data[ "rto_id" ] = (string) $rto->id;
                $data[ "cc" ] = "";
                $data[ "gvw" ] = "";
                $data[ "pcv" ] = "";
                if ( $vehicleType == "2 Wheeler" || $vehicleType == "4 Wheeler" )
                {
                    $data[ "cc" ] =
                        getVehicleCapacity (
                            $vehicleType,
                            "cc",
                            $getMmv[ "data" ][ "providers" ][ 0 ][ "cc" ]
                        ) ?? 0;
                }
                if ( $vehicleType == "Commercial GCV" )
                {
                    $data[ "gvw" ] =
                        getVehicleCapacity (
                            $vehicleType,
                            "gvw",
                            $getMmv[ "data" ][ "providers" ][ 0 ][ "gvw" ]
                        ) ?? 0;
                }
                if ( $vehicleType == "Commercial PCV" )
                {
                    $data[ "pcv" ] =
                        getVehicleCapacity (
                            $vehicleType,
                            "pcv",
                            $getMmv[ "data" ][ "providers" ][ 0 ][ "seating_capacity" ]
                        ) ?? 0;
                }
                // $data['policy_period'] = $request->policy_period;
                $data[ "policy_type" ] = $lead->product_code;
                $data[ "business_type" ] = $bussinessType;
                $data[ "fuel_type" ] = ucfirst ( $lead->fuel_type );

                $state_id = $data[ "state_id" ];
                $rto_id = $data[ "rto_id" ];
                $make_id = $data[ "make_id" ];
                // $model_id = $data["model_id"];
                $fuel_type = $data[ "fuel_type" ];

                $pcv = $data[ "pcv" ];
                $gvw = $data[ "gvw" ];
                $cc = $data[ "cc" ];
                $vehicle_category = $data[ "vehicle_category" ];

                $rules = GridRule::join (
                    "agent_payouts",
                    "grid_rules.id",
                    "=",
                    "agent_payouts.rule_id"
                )
                    ->select (
                        "grid_rules.id",
                        "commission",
                        "commission_type",
                        "od_comm",
                        "tp_comm",
                        "net_comm",
                        "agent_payouts.payout",
                        "agent_payouts.od_payout",
                        "agent_payouts.tp_payout",
                        "agent_payouts.net_payout",
                        "agent_payouts.tp_payout_first_year",
                        "effective_start_date"
                    )
                    ->where ( "agent_payouts.agent_id", $data[ "agent_id" ] )
                    ->where ( "bussiness_type", $data[ "business_type" ] )
                    ->where ( "provider_id", $providerId )
                    ->where ( function ($query) use ($state_id)
                    {
                        if ( $state_id )
                        {
                            $query
                                ->whereJsonContains ( "state_id", $state_id )
                                ->orWhereJsonContains ( "state_id", "select_all" );
                        }
                    } )
                    ->where ( function ($query) use ($rto_id)
                    {
                        if ( $rto_id )
                        {
                            $query
                                ->whereJsonContains ( "rto_id", $rto_id )
                                ->orWhereJsonContains ( "rto_id", "select_all" );
                        }
                    } )
                    ->where ( function ($query) use ($make_id)
                    {
                        if ( !empty ( $make_id ) )
                        {
                            $query->orWhereJsonContains ( "make_id", $make_id );
                        }
                    } )
                    // ->whereJsonContains('model_id', $data['model_id'])
                    ->whereJsonContains ( "fuel_type", $data[ "fuel_type" ] )
                    ->where ( function ($query) use ($vehicleAge, $data)
                    {
                        if ( $data[ "business_type" ] == "New Business" )
                        {
                            $query->where ( "vehicle_age", "0 Year" );
                        } else
                        {
                            $query->whereRaw (
                                '? BETWEEN CAST(SUBSTRING_INDEX(vehicle_age, "-", 1) AS UNSIGNED) AND CAST(SUBSTRING_INDEX(SUBSTRING_INDEX(vehicle_age, " ", 1), "-", -1) AS UNSIGNED)',
                                [ $vehicleAge ]
                            );
                        }
                    } )
                    ->where ( "vehicle_type", $data[ "vehicle_type" ] )
                    ->whereJsonContains ( "vehicle_category", $data[ "vehicle_category" ] )
                    ->where ( "policy_type", $data[ "policy_type" ] )
                    // ->where('policy_period', $data['policy_period'])
                    ->when ( $cc, function ($query, $cc)
                    {
                        return $query->whereJsonContains ( "cubic_capacity", $cc );
                    } )
                    ->when ( $gvw, function ($query, $gvw)
                    {
                        return $query->whereJsonContains ( "goods_cubic_capacity", $gvw );
                    } )
                    ->when ( $pcv, function ($query, $pcv)
                    {
                        return $query->whereJsonContains (
                            "passenger_carrying_capacity",
                            $pcv
                        );
                    } )
                    ->where (
                        "effective_start_date",
                        "<=",
                        Carbon::now ()->format ( "Y-m-d" )
                    )
                    ->where ( "status", 1 )
                    ->where ( "is_deleted", 0 )
                    ->orderBy ( "effective_start_date", "DESC" )
                    ->get ();

                // dd($data ,$rules);

                if ( count ( $rules ) > 0 )
                {
                    foreach ( $rules as $rule )
                    {
                        $commission = json_decode ( $rule->commission );
                        $commissionType = $rule->commission_type;

                        $outOdComm = $rule->od_payout ?? 0;
                        $outTpComm = $rule->tp_payout ?? 0;
                        $outNetComm = $rule->net_payout ?? 0;

                        if ( $commissionType === 'percentage' )
                        {
                            $outOdAmt = in_array ( "OD", $commission ) && $odPremium > 0 ? ( $odPremium * $outOdComm ) / 100 : 0;
                            $outTpAmt = in_array ( "TP", $commission ) && $tpPremium > 0 ? ( $tpPremium * $outTpComm ) / 100 : 0;
                            $outNetAmt = in_array ( "Net", $commission ) && $netPremium > 0 ? ( $netPremium * $outNetComm ) / 100 : 0;
                        } else
                        {
                            $outOdAmt = $outOdComm;
                            $outTpAmt = $outTpComm;
                            $outNetAmt = $outNetComm;
                        }

                        $rewardPoints = ( $outOdAmt + $outTpAmt + $outNetAmt ) / 10;
                    }
                }
            } elseif ( $lead->quote_type == 'health' )
            {
                $leads = HealthQuote::where ( 'enquiry_id', $lead->enquiry_id )->first ();

                $data[ 'cover_type' ] = $leads->cover_type ?? null;
                $data[ 'policy_type' ] = $leads->policy_type ?? null;
                $data[ 'sum_insured' ] = $leads->sum_insured ?? null;
                $data[ 'agent_id' ] = $lead->agent_id ?? null;
                $data[ 'provider' ] = $providerId ?? null;

                $rules = HealthRule::join (
                    "agent_payouts",
                    "health_rules.id",
                    "=",
                    "agent_payouts.health_rule_id"
                )
                    ->select ( 'health_rules.id', 'commission', 'commission_type', 'agent_payouts.net_payout', 'effective_start_date' )
                    ->where ( "agent_payouts.agent_id", $data[ "agent_id" ] )
                    ->where ( 'business_type', $data[ 'policy_type' ] )
                    ->where ( 'provider_id', $data[ 'provider' ] )
                    ->where ( 'cover_type', $data[ 'cover_type' ] )
                    // ->where('sum_insured_type', $data['sum_insured_type'])
                    // ->where('plan_id', $data['plan_id'])
                    ->when ( isset ( $data[ 'sum_insured' ] ), function ($query) use ($data)
                    {
                        $query->where ( function ($q) use ($data)
                        {
                            // Check if $sum_insured is between sum_insured_min and sum_insured_max
                            $q->where ( 'sum_insured_min', '<=', $data[ 'sum_insured' ] )
                                ->where ( 'sum_insured_max', '>=', $data[ 'sum_insured' ] );
                        } );
                    } )
                    ->where ( 'status', 1 )
                    ->where ( 'is_deleted', '0' )
                    ->where ( 'effective_start_date', '<=', Carbon::now ()->format ( "Y-m-d" ) )
                    ->orderBy ( "effective_start_date", "DESC" )
                    ->get ();

                // dd($data,$rules);
                if ( count ( $rules ) > 0 )
                {
                    foreach ( $rules as $rule )
                    {
                        $commission = $rule->commission;
                        $commissionType = $rule->commission_type;

                        $outNetComm = $rule->net_payout ?? 0;

                        if ( $commissionType === 'percentage' )
                        {
                            $outNetAmt = ( $commission == "Net" && $netPremium > 0 ) ? ( $netPremium * $outNetComm ) / 100 : 0;
                        } else
                        {
                            $outNetAmt = $outNetComm;
                        }

                        $rewardPoints = $outNetAmt / 10;
                    }
                }
            }

            return $rewardPoints;
        } catch ( Exception $e )
        {
            Log::info ( 'Commission fetch error: ' . $e->getMessage () );
            Log::info ( 'Commission fetch error line: ' . $e->getLine () );
        }
    }
    public static function assignRewardPoints(
        $enquiryId,
        $providerId,
        $odPremium = 0,
        $tpPremium = 0,
        $netPremium = 0
    ) {
        try
        {
            $pointAssigned = false;
            $lead = Leads::where ( "enquiry_id", $enquiryId )->first ();

            if ( $lead )
            {

                if ( $lead->quote_type == "motor" )
                {
                    $policy = CustomerPolicyModel::where (
                        "enquiry_id",
                        $enquiryId
                    )->first ();

                    $case = $lead->policy_case;
                    $bussinessType = "";
                    $vehicleAge = 0;
                    if ( $case == "new" )
                    {
                        $bussinessType = "New Business";
                    } else
                    {
                        $bussinessType = "Rollover";
                    }
                    if ( $bussinessType )
                    {
                        if ( $bussinessType == "Rollover" )
                        {
                            if ( isset ( $lead->registration_date ) )
                            {
                                $regDate = $lead->registration_date;
                                $regDate = Carbon::parse ( $regDate );
                                $currentDate = Carbon::now ();
                                $age = $currentDate->diffInYears ( $regDate );
                                $vehicleAge = $age . " Year";
                            }
                        }
                    }

                    if ( $lead->vehicle_type == "bike" )
                    {
                        $vehicleType = "2 Wheeler";
                    } elseif ( $lead->vehicle_type == "car" )
                    {
                        $vehicleType = "4 Wheeler";
                    } elseif ( $lead->vehicle_type == "pcv" )
                    {
                        $vehicleType = "Commercial PCV";
                    } elseif ( $lead->vehicle_type == "gcv" )
                    {
                        $vehicleType = "Commercial GCV";
                    } elseif ( $lead->vehicle_type == "mcv" )
                    {
                        $vehicleType = "Misc D";
                    }

                    $modelId = $lead->model_id ?? null;

                    $rto = Rto::select ( "id", "rtoCode", "state" )
                        ->where ( "rtoCode", $lead->rto_code )
                        ->first ();
                    $insuranceProvider = InsuranceProvider::select (
                        "id",
                        "provider_name"
                    )
                        ->where (
                            "short_name",
                            "like",
                            "%" . $policy->insurance_provider . "%"
                        )
                        ->first ();
                    $stateId = StateNew::select ( "id", "state_name" )
                        ->where ( "state_name", $rto->state )
                        ->first ();

                    $getMmv = self::getMmvById ( $lead->object_id );

                    $vehicleBody =
                        isset ( $getMmv ) &&
                        isset ( $getMmv[ "data" ] ) &&
                        isset ( $getMmv[ "data" ][ "body_type" ] )
                        ? $getMmv[ "data" ][ "body_type" ]
                        : "";
                    $vehicle =
                        isset ( $getMmv ) &&
                        isset ( $getMmv[ "data" ] ) &&
                        isset ( $getMmv[ "data" ][ "vehicle_type" ] )
                        ? $getMmv[ "data" ][ "vehicle_type" ]
                        : "";
                    $fuelType =
                        isset ( $getMmv ) &&
                        isset ( $getMmv[ "data" ] ) &&
                        isset ( $getMmv[ "data" ][ "fuel_type" ] )
                        ? $getMmv[ "data" ][ "fuel_type" ]
                        : "";

                    $vehicleCategory = Helpers::getVehicleCategory (
                        $vehicleType,
                        $vehicleBody,
                        $vehicle,
                        $fuelType
                    );

                    $data[ "agent_id" ] = $lead->agent_id;
                    $data[ "provider" ] = $insuranceProvider->id ?? null;
                    $data[ "vehicle_type" ] = $vehicleType;
                    $data[ "vehicle_category" ] = $vehicleCategory;
                    $data[ "vehicle_age" ] = $vehicleAge;
                    $data[ "make_id" ] = (string) $lead->make_id;
                    // $data['model_id'] = (string)$modelId;
                    $data[ "state_id" ] = (string) $stateId->id;
                    $data[ "rto_id" ] = (string) $rto->id;
                    $data[ "cc" ] = "";
                    $data[ "gvw" ] = "";
                    $data[ "pcv" ] = "";

                    if ( $vehicleType == "2 Wheeler" || $vehicleType == "4 Wheeler" )
                    {
                        $data[ "cc" ] =
                            getVehicleCapacity (
                                $vehicleType,
                                "cc",
                                $getMmv[ "data" ][ "providers" ][ 0 ][ "cc" ]
                            ) ?? 0;
                    }
                    if ( $vehicleType == "Commercial GCV" )
                    {
                        $data[ "gvw" ] =
                            getVehicleCapacity (
                                $vehicleType,
                                "gvw",
                                $getMmv[ "data" ][ "providers" ][ 0 ][ "gvw" ]
                            ) ?? 0;
                    }
                    if ( $vehicleType == "Commercial PCV" )
                    {
                        $data[ "pcv" ] =
                            getVehicleCapacity (
                                $vehicleType,
                                "pcv",
                                $getMmv[ "data" ][ "providers" ][ 0 ][ "seating_capacity" ]
                            ) ?? 0;
                    }
                    // $data['policy_period'] = $request->policy_period;
                    $data[ "policy_type" ] =
                        $lead->product_code == "saod" ? "od" : $lead->product_code;
                    $data[ "business_type" ] = $bussinessType;
                    $data[ "fuel_type" ] = ucfirst ( $lead->fuel_type );

                    $state_id = $data[ "state_id" ];
                    $rto_id = $data[ "rto_id" ];
                    $make_id = $data[ "make_id" ];
                    // $model_id = $data["model_id"];
                    $fuel_type = $data[ "fuel_type" ];

                    $pcv = $data[ "pcv" ];
                    $gvw = $data[ "gvw" ];
                    $cc = $data[ "cc" ];

                    $rules = GridRule::join (
                        "agent_payouts",
                        "grid_rules.id",
                        "=",
                        "agent_payouts.rule_id"
                    )
                        ->select (
                            "grid_rules.id",
                            "agent_payouts.tp_payout_first_year",
                            "commission",
                            "od_comm",
                            "tp_comm",
                            "net_comm",
                            "commission_type",
                            "agent_payouts.payout",
                            "agent_payouts.od_payout",
                            "agent_payouts.tp_payout",
                            "agent_payouts.net_payout",
                            "effective_start_date"
                        )
                        ->where ( "agent_payouts.agent_id", $data[ "agent_id" ] )
                        ->where ( "bussiness_type", $data[ "business_type" ] )
                        ->where ( "provider_id", $data[ "provider" ] )
                        ->where ( function ($query) use ($state_id)
                        {
                            if ( $state_id )
                            {
                                $query
                                    ->whereJsonContains ( "state_id", $state_id )
                                    ->orWhereJsonContains ( "state_id", "select_all" );
                            }
                        } )
                        ->where ( function ($query) use ($rto_id)
                        {
                            if ( $rto_id )
                            {
                                $query
                                    ->whereJsonContains ( "rto_id", $rto_id )
                                    ->orWhereJsonContains ( "rto_id", "select_all" );
                            }
                        } )
                        ->where ( function ($query) use ($make_id)
                        {
                            $query->orWhereJsonContains ( "make_id", $make_id );
                        } )
                        // ->whereJsonContains('model_id', $data['model_id'])
                        ->whereJsonContains ( "fuel_type", $data[ "fuel_type" ] )
                        ->where ( function ($query) use ($vehicleAge, $data)
                        {
                            if ( $data[ "business_type" ] == "New Business" )
                            {
                                $query->where ( "vehicle_age", "0 Year" );
                            } else
                            {
                                $query->whereRaw (
                                    '? BETWEEN CAST(SUBSTRING_INDEX(vehicle_age, "-", 1) AS UNSIGNED) AND CAST(SUBSTRING_INDEX(SUBSTRING_INDEX(vehicle_age, " ", 1), "-", -1) AS UNSIGNED)',
                                    [ $vehicleAge ]
                                );
                            }
                        } )
                        ->where ( "vehicle_type", $data[ "vehicle_type" ] )
                        ->whereJsonContains (
                            "vehicle_category",
                            $data[ "vehicle_category" ]
                        )
                        ->where ( "policy_type", $data[ "policy_type" ] )
                        // ->where('policy_period', $data['policy_period'])
                        ->when ( $cc, function ($query, $cc)
                        {
                            return $query->whereJsonContains ( "cubic_capacity", $cc );
                        } )
                        ->when ( $gvw, function ($query, $gvw)
                        {
                            return $query->whereJsonContains (
                                "goods_cubic_capacity",
                                $gvw
                            );
                        } )
                        ->when ( $pcv, function ($query, $pcv)
                        {
                            return $query->whereJsonContains (
                                "passenger_carrying_capacity",
                                $pcv
                            );
                        } )
                        ->where ( "status", 1 )
                        ->where (
                            "effective_start_date",
                            "<=",
                            Carbon::now ()->format ( "Y-m-d" )
                        )
                        ->where ( "is_deleted", 0 )
                        ->orderBy ( "effective_start_date", "DESC" )
                        ->get ();

                    // dd($data,$rules);
                    $comment = "No rule added for this";
                    $rewardPoints = 0;

                    if ( count ( $rules ) > 0 )
                    {
                        foreach ( $rules as $rule )
                        {
                            $tableName = "motor_rules";

                            $commission = json_decode ( $rule->commission );
                            $commissionType = $rule->commission_type;

                            $outOdComm = $rule->od_payout ?? 0;
                            $outTpComm = $rule->tp_payout ?? 0;
                            $outNetComm = $rule->net_payout ?? 0;

                            if ( $commissionType === 'percentage' )
                            {
                                $outOdAmt = in_array ( "OD", $commission ) && $odPremium > 0 ? ( $odPremium * $outOdComm ) / 100 : 0;
                                $outTpAmt = in_array ( "TP", $commission ) && $tpPremium > 0 ? ( $tpPremium * $outTpComm ) / 100 : 0;
                                $outNetAmt = in_array ( "Net", $commission ) && $netPremium > 0 ? ( $netPremium * $outNetComm ) / 100 : 0;
                            } else
                            {
                                $outOdAmt = $outOdComm;
                                $outTpAmt = $outTpComm;
                                $outNetAmt = $outNetComm;
                            }

                            $rewardPoints = ( $outOdAmt + $outTpAmt + $outNetAmt ) / 10;

                            $comment =
                                $rewardPoints .
                                " Reward points assigned for online motor quote";

                            $rewardPointCheck = RewardPoint::where (
                                "online_quote_id",
                                $lead->id
                            )->exists ();

                            if ( !$rewardPointCheck )
                            {
                                $inOdComm = $rule->od_comm ?? 0;
                                $inTpComm = $rule->tp_comm ?? 0;
                                $inNetComm = $rule->net_comm ?? 0;

                                if ( $commissionType === 'percentage' )
                                {
                                    $inOdAmt = in_array ( "OD", $commission ) && $odPremium > 0 ? ( $odPremium * $inOdComm ) / 100 : 0;
                                    $inTpAmt = in_array ( "TP", $commission ) && $odPremium > 0 ? ( $tpPremium * $inTpComm ) / 100 : 0;
                                    $inNetAmt = in_array ( "Net", $commission ) && $netPremium > 0 ? ( $netPremium * $inNetComm ) / 100 : 0;
                                } else
                                {
                                    $inOdAmt = $inOdComm;
                                    $inTpAmt = $inTpComm;
                                    $inNetAmt = $inNetComm;
                                }

                                $rule = GridRule::find ( $rule->id );

                                $commissionAmount = ( $inOdAmt + $inTpAmt + $inNetAmt );

                                $assignPoints = new RewardPoint();
                                $assignPoints->agent_id = $data[ "agent_id" ];
                                $assignPoints->rule_id = $rule ? $rule->id : null;
                                $assignPoints->table_name = $tableName;
                                $assignPoints->online_quote_id = $lead->id;
                                $assignPoints->quote_type = "motor";
                                $assignPoints->points = $rewardPoints;
                                $assignPoints->amount = $rewardPoints * 10;
                                $assignPoints->comment = $comment;
                                $assignPoints->in_od_comm = $inOdComm;
                                $assignPoints->in_tp_comm = $inTpComm;
                                $assignPoints->in_net_comm = $inNetComm;
                                $assignPoints->out_od_comm = $outOdComm;
                                $assignPoints->out_tp_comm = $outTpComm;
                                $assignPoints->out_net_comm = $outNetComm;
                                $assignPoints->commission = $commissionAmount;
                                $assignPoints->rule_details = json_encode ( $rule->toArray () );
                                $assignPoints->save ();

                                if ( $assignPoints )
                                {
                                    $pointAssigned = true;
                                }
                            }
                        }
                    }
                } elseif ( $lead->quote_type == "health" )
                {
                    $leads = HealthQuote::where ( 'enquiry_id', $lead->enquiry_id )->first ();
                    $policy = HealthPolicy::where ( 'enquiry_id', $lead->enquiry_id )->first ();

                    $insuranceProvider = InsuranceProvider::select (
                        "id",
                        "provider_name"
                    )
                        ->where (
                            "short_name",
                            "like",
                            "%" . $policy->insurance_provider . "%"
                        )
                        ->first ();

                    $data[ 'cover_type' ] = $leads->cover_type ?? null;
                    $data[ 'policy_type' ] = $leads->policy_type ?? null;
                    $data[ 'sum_insured' ] = $leads->sum_insured ?? null;
                    $data[ 'agent_id' ] = $lead->agent_id ?? null;
                    $data[ 'provider' ] = $insuranceProvider->id ?? null;

                    $rules = HealthRule::join (
                        "agent_payouts",
                        "health_rules.id",
                        "=",
                        "agent_payouts.health_rule_id"
                    )
                        ->select ( 'health_rules.id', 'commission', 'net_comm', 'commission_type', 'agent_payouts.payout', 'agent_payouts.od_payout', 'agent_payouts.tp_payout', 'agent_payouts.net_payout', 'agent_payouts.tp_payout_first_year', 'effective_start_date' )
                        ->where ( "agent_payouts.agent_id", $data[ "agent_id" ] )
                        ->where ( 'business_type', $data[ 'policy_type' ] )
                        ->where ( 'provider_id', $data[ 'provider' ] )
                        ->where ( 'cover_type', $data[ 'cover_type' ] )
                        // ->where('sum_insured_type', $data['sum_insured_type'])
                        // ->where('plan_id', $data['plan_id'])
                        ->when ( isset ( $data[ 'sum_insured' ] ), function ($query) use ($data)
                        {
                            $query->where ( function ($q) use ($data)
                            {
                                // Check if $sum_insured is between sum_insured_min and sum_insured_max
                                $q->where ( 'sum_insured_min', '<=', $data[ 'sum_insured' ] )
                                    ->where ( 'sum_insured_max', '>=', $data[ 'sum_insured' ] );
                            } );
                        } )
                        ->where ( 'status', 1 )
                        ->where ( 'is_deleted', '0' )
                        ->where ( 'effective_start_date', '<=', Carbon::now ()->format ( "Y-m-d" ) )
                        ->orderBy ( "effective_start_date", "DESC" )
                        ->get ();

                    // dd($rule);
                    $comment = 'No rule added for this';
                    $rewardPoints = 0;

                    $amount = 0;
                    $tableName = 'health_rules';
                    $netPayout = 0;
                    $netPremium = (int) $netPremium;

                    if ( isset ( $rules ) )
                    {
                        if ( count ( $rules ) > 0 )
                        {
                            foreach ( $rules as $rule )
                            {
                                $commission = $rule->commission;
                                $commissionType = $rule->commission_type;

                                $outNetComm = $rule->net_payout ?? 0;

                                if ( $commissionType === 'percentage' )
                                {
                                    $outNetAmt = ( $commission == "Net" && $netPremium > 0 ) ? ( $netPremium * $outNetComm ) / 100 : 0;
                                } else
                                {
                                    $outNetAmt = $outNetComm;
                                }

                                $rewardPoints = $outNetAmt / 10;
                            }
                        }

                        $comment = $rewardPoints . ' Reward points assigned for health quote';

                        $rewardPointCheck = RewardPoint::where (
                            "online_quote_id",
                            $lead->id
                        )->exists ();

                        if ( !$rewardPointCheck )
                        {
                            $inNetComm = $rule->net_comm ?? 0;

                            if ( $commissionType === 'percentage' )
                            {
                                $inNetAmt = ( $commission == "Net" && $netPremium > 0 ) ? ( $netPremium * $inNetComm ) / 100 : 0;
                            } else
                            {
                                $inNetAmt = $inNetComm;
                            }

                            $rule = GridRule::find ( $rule->id );

                            $commissionAmount = $inNetAmt / 10;

                            $assignPoints = new RewardPoint();
                            $assignPoints->agent_id = $data[ 'agent_id' ];
                            $assignPoints->health_rule_id = $rule ? $rule->id : null;
                            $assignPoints->table_name = $tableName;
                            $assignPoints->online_quote_id = $lead->id;
                            $assignPoints->quote_type = $lead->quote_type;
                            $assignPoints->points = $rewardPoints;
                            $assignPoints->amount = $rewardPoints * 10;
                            $assignPoints->comment = $comment;
                            $assignPoints->in_net_comm = $inNetComm;
                            $assignPoints->out_net_comm = $outNetComm;
                            $assignPoints->commission = $commissionAmount;
                            $assignPoints->rule_details = json_encode ( $rule->toArray () );
                            $assignPoints->save ();

                            if ( $assignPoints )
                            {
                                $pointAssigned = true;
                            }
                        }
                    }
                }
            }
            return $pointAssigned;
        } catch ( Throwable $e )
        {
            Log::info ( 'Assign reward point error: ' . $e->getMessage () );
            Log::info ( 'Assign reward point error line: ' . $e->getLine () );
        }
    }
    public static function mmv_api_call( $apiUrl, $method )
    {
        try
        {
            $ch = curl_init ();
            curl_setopt_array ( $ch, [ 
                CURLOPT_URL => $apiUrl,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_ENCODING => "",
                CURLOPT_MAXREDIRS => 10,
                CURLOPT_TIMEOUT => 60,
                CURLOPT_FOLLOWLOCATION => true,
                CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
                CURLOPT_CUSTOMREQUEST => $method,
                CURLOPT_HTTPHEADER => [ "Content-Type: application/json" ],
            ] );
            $response = curl_exec ( $ch );
            $httpCode = curl_getinfo ( $ch, CURLINFO_HTTP_CODE );
            curl_close ( $ch );
            $responseArray = json_decode ( $response, true );
            if ( $httpCode == 200 )
            {
                return [ 
                    "status" => true,
                    "data" => $responseArray[ "data" ],
                    "message" => "Success",
                ];
            } else
            {
                return [ 
                    "status" => false,
                    "data" => [],
                    "message" => $responseArray[ "message" ] ?? 'Unknown error',
                ];
            }
        } catch ( Exception $e )
        {
            return [ 
                "status" => false,
                "data" => [],
                "message" => $e->getMessage (),
            ];
        }
    }
    public static function getMmvById( $objectId )
    {
        $environment = config ( "app.env", "production" );

        $apiUrl =
            $environment === "production"
            ? config ( "constant.mmv_base_url.prod_url" )
            : config ( "constant.mmv_base_url.dev_url" );

        // Build the API URL with query parameters
        $apiUrl .= "get-mmv-by-id?id=" . $objectId;

        // Call the API
        $response = self::mmv_api_call ( $apiUrl, "GET" );

        return $response;
    }
}
