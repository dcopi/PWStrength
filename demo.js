var Entropy;

(function () {

    /**
     * @constructor
     * @class Entropy
     * Entropy is a singleton designed to calculate the entropy value of a user's password based on
     * the National Institute of Standards and Technology special publication 800-63.
     * http://csrc.nist.gov/publications/nistpubs/800-63-1/SP-800-63-1.pdf (Appendix A: Estimating Entropy and Strength)
     * @param pw {String} The user's password.
     */
    Entropy = function (pw) {
        if (typeof pw != "string") { pw = ""; }

        var charset  = this.getCharsetInfo(pw), // returns {size: <number of possible characters>, count: <number of character sets the password matched>}
            compBits = this.calcCompositionBits(pw, charset.count),  // retrieve bits for composition rules
            dictBits = this.calcDictionaryBits(pw); // retrieve bits for not appearing in dictonary

        this.password = pw;
        this.entropy = (charset.size <= 0) ? 0 : Math.floor(Math.log(charset.size) * (pw.length / Math.log(2))) + compBits + dictBits;
        this.inDict   = (dictBits === 0 && Entropy.DICT[pw.toLowerCase()]);  // true if password is in the dictionary
        this.charset  = charset;  // info about the size of the character set used to calculate the entropy
    };

    Entropy.prototype = {

        /** @attr password {String} The password used for the calculation. */
        password: "",

        /** @attr entropy {Number} The calculated entropy value. */
        entropy: 0,

        /** @attr inDict {Boolean} "true" if the password value is in the dictionary. */
        inDict: false,

        /**
         * @attr charset {Object} Size and count of the character set to use for
         *      calculating entropy. "size" attribute is the number of possible
         *      characters. "count" attribute is the number of character sets the
         *      password matched.
         */
        charset: null,

        /**
         * @method calcCompositionBits
         * Determine how many "bits" to add to the entropy value for a given password
         * based on the length of the password and the number of character sets it is in.
         * @param pw {String} The user's password.
         * @param cnt {Number} How many character sets the password is in.
         * @return {Number}
         */
        calcCompositionBits: function (pw, cnt) {
            var ln = pw.length, bits = 0;

            if ( ln >= 4 && cnt >= 3) {
                if (ln >= 8) { bits = 6; }
                else if (ln == 7) { bits = 5; }
                else if (ln >= 5 && ln <= 6) { bits = 3; }
                else if (ln == 4) { bits = 2; }
            }
            return bits;
        },

        /**
         * @method getCharsetInfo
         * Calculates the size of the character set used for the entropy calculation
         * and the number of character sets the password inhabits.
         * @param pw {String} The user's password.
         * @return {Object} Size and count of the character set to use for calculating entropy.
         *      "size" attribute is the number of possible characters. "count" attribute is
         *      the number of character sets the password matched.
         */
        getCharsetInfo: function (pw) {
            var rx=Entropy.CHARSET_RX, size=0, count=0;

            if (rx.lc.test(pw)) { size += 26; count += 1; }  // lowercase
            if (rx.uc.test(pw)) { size += 26; count += 1; } // uppercase
            if (rx.num.test(pw)) { size += 10; count += 1; } // number
            if (rx.sp.test(pw)) { size += 1; count += 1; } // space
            if (rx.sym_upper.test(pw)) { size += 16; count += 1; } // Upper keyboard symbols
            if (rx.sym_lower.test(pw)) { size += 16; count += 1; } // lower keyboard symbols
            // non-keyboard symbols. Charset will be all unicode characters (minus the 94 standard keyboard characters).
            // It is unlikely that anyone with a standard keyboard will test true here
            if (rx.non_keyboard.test(pw)) { size += (65535-94); count += 1; }

            return {size: size, count: count};
        },

        /**
         * @method calcDictionaryBits
         * Determine how many "bits" to add to the entropy value based on the password's
         * length and whether the password is in the dictionary. A bonus of up to 6 bits of
         * entropy can be added for an extensive dictionary check. The specific number of
         * bits is calculated as follows:
         * (1) (length < 4) || (password in dictionary) is 0 bits.
         * (2) (length <= 6) is length of pw (4, 5, or 6 bits).
         * (3) (length > 6 && length < 20) is 6 bits.
         * @param pw {String} The user's password.
         * @return {Number} The number of bits.
         */
        calcDictionaryBits: function (pw) {
            var ln = pw.length;
            return ( ln>=4 && ln<20 && !Entropy.DICT[pw.toLowerCase()] ) ? Math.min(ln, 6) : 0;
        }



    }; // -- eo prototype


    Entropy.DICT = unpackDictList("A!@#$%F^G&H*A.,mnEbA/.,mEnFbBdev/nullBetc/passwdBusr/groupA0000E0F0G0H0D7C7007B213C46D9A1022D9E3F8Csne1B111E1F1G1H1B209C12E12D3D4D7C25C3098D123D321D4E5F6G7H8EqwerDabcDgoB313E13D6C32C579B412C30C430B701dC1717B812overtureD8E18B900D1D2D3D4D5D6D7D8D9C10D1D2D3D4D5D6D7D8D9C20D1D2D3D4D5D6D7D8D9C30D1D2D3D4D5D6D7D8D9C40D1D2D3D4D5D6D7D8D9C50D1D2D3D4D5D6D7D8D9C60D1D2D3D4D5D6D7D8D9C70D1D2D3D4D5D6D7D8D9C80D1D2D3D4D5D6D7D8D9C90D1D2D3D4D5D6D7D8D9Ba2b3cBchrisBkittyBp2o3iBq2w3eCw23eBsanjoseA2000D1D2D3D4D5D6D7D8D9C10D2D3D4D5D6D7D8D9C20D1D2D3D4D5D6D7D8D9C30D1D2D3D4D5D6D7D8B112E2112B200C22E2F2G2H2C52BkidsBwelcomeA3010B112C41B333E3F3G3H3B533BbearsA4.2bsdC3bsdB055C77mashB2bsdB3bsdB444E4F44H4B788B854BrunnerA5050B121B252B4321B555E5F5G5H5B683B7chevyBand5A6262B301B54321B666E6F6G6H6B969E69Czulu4zA7777E7F7G7H7B89456BdwarfsA80486B675309B7654321B888E8F8G8H8A90210B11scFturboDturboB2072B999E9F9G9H9A;lk;lkDasdA@#$%^&Aa12345Cb2c3Gd4BaaaEaFaGaHaCrdvarkDonDtiBbacabDdabdooCbotFtDyCc123DdE123H4EeFfGgCdenaceDolDulFkafFlahErChijitEramCigailCoutCracadabraIverEhamErCsolutBcaciaDdemiaHcCceptEssDordEuntHsCknakCropolisCtionEveDorCuraBdamEsCelCibDdasDneCminF1FistIratorCrianGnaHeEenGneDockCultCventurDilBeneasCrobicsBfreshDicaEdCterBgainCentCgieFsCnesBhideeCmedEtBikmanCleenCmeeCrborneDcraftDheadDplaneDwolfBjaiDyBkhilCi123DkoBlainDmgirDnDsEkaEtairDyneCbanyEtrosIsDertGoCcaponeCejandrDnaDrtDssandDxE1EandeIrHrEendrEiaFsCfaroDredCgebraCiasFesDcaEeF1EiaDenFsDnaEeDsaEonClahEnDegroEnDisonDoDstateCohaDkCphaF1FbetDineCtafEmiraDheaDimaG1CvaDinCwaysCysonEsaBmadeusDndaG1DrEjitEpreeDzingCberCelieDricaH7CigaCorphousDsDurCrilBn-jenCacondaDlEogDntFhDstasiCchanaEorCdersGonDiDreF1FaG1GsFwG!G1EoidFmacheGedEzejDyCelieseDwpassCgelF1FaG1FikaFsErineDieF1DusCilDmalG houseGhouseGsDsDtaCjanaDenCnaElenaFiseEmariDeEliEtteDiEeConEymousCswerCtaresDhonyEropogenicDoineEnFioFyCumber1HoneDpaFmDragCvilsCythingBpacheColloG13CpleF1F2FiiFpieFsCrilCtivaBquaEriousGusBragornDmDshCbenzCchieFtectDticCdentCeleneCiaEdneEneDelFlaDfDjitDndamDstotleDzonaCjunFasaCleneCmandGoDondCnoldConDundCrowCsenalDhadCtemisDhurDieEstDyCunEaCvindBsadDpCdfE1234E;lkjEasdfEgFhGjHkEjklH;DlkjChimaEshDleyG1DokDrafDtonDutoshCianCjeetCpenCsholeDmunchCterixBt&tCandtChanassDenaClantaCmosphereCseCtilaCulBudieDraEeyCgustGinCreliusCstinCthorDumnBvalonDtarCengerEirCniCrahamBwayE!CesomeByeletClmerBzamCizEiCtecsCureAbabakDeEsDiesDyEdollElon5CcchusDhDkdoorErubEupCdassDboyDgerDtimesCgladyDwomanChramCileyCkedpotatoeErDshiClakrisEsFubrDdoDkrishDlardEsCmbiEooCnanaGsFeDcroftDditDgDksDzaiCrakaDbEaraEerEieDfEerEingDitoneDnEesFyG1EieEyardDonF harkonnenFharkonnenDretGtEyDtEmanEonCsebalHlDfEulDicElDkarEetGbHaIllDsEoonDtardDukiCtcaveEhEomputerDmanG1EobileCystateBballCbbEbFbGbHbBeachFesDgleDmmeupDnerEieEsDrEsDstFyDterEitElesEriceDutifuIlFyDverEisG1CbeCcauseDcaDkyCefDnDrDthovenCforeChnamClgiumDizeDlEaEeEowDmontDovedCngtDjaminEiDnetGtEyDoitDsonDtDyDzCowulfCppeCresforDhanuDkeleyDlinGerGwallDnardHoEhardEieDryDtEhaDylCstCtaEcamDhEanyDsieEyDterEieEyCverlyBharatDvaniCoothapBiayCcameralDhngaEonCenveniCgalDbenEirdEossFyErotherEucksDcockHsDdealEogEudeDfootDglesEuyDhipsEouseDjokeDmacFnEouthDredEoomDsecretDtitsEoeCkerClboDiameeDlEcEieEsEyF1CmboFeDmerCndDgEoDkyDodCoboyDchemDlogyCrdE33EieEyDgetGtaEitDthdayCscuitDhopDmillahCtchFinH'HgDemeDterCzhanBjornBlackFbootFieFjackDderunnerDhDineErDkeDncheDsterDzerCeepFingFsCindsDssDtzDzzardCondeFieFsG1DodEmcountyDwEfishEjobEmeEoffCssCueEbirdFlazerEeyesEfishEjeanElineEsFkyEvelvetBoatCbbiFjoEyDcatCdyshopCeingCgartDeyDusCleslawCmbayCndE007DerDgDitaDjourDkersDnEieDsaiDzaiEoCobieGsEooEysDgerEieDkEemGdannoEitDmerDnDsterDtsFieDzieCrisDnagaiCscoDsDtonCthCulderDrbonEneG-againGagainCwlingCxerFsCydDwonderCzoBradE&janetEfordEjanetEleyEnjanetDinFdeadDnchEd-n-janetFiFonFyEislaDsilDtDvenewworldFsDzilCeakoutEstGfeedGsDndaGnFenEtDtEonEtDwsterCianDcklesFoutDdgeGsGtHtDefcaseDghtDngEkleyDtainCoadwayDkenheartFrDmbergDncoGsEteDokeFsDthelGrHsDwnFsCuceDnoDtusCyanFtDceDnBsd4DunixBubbaF1FhGlahFlahEleGsCckEarooEsCddEahEhaFistEyDgieDliteCffaloEettEyCgsEbunnyEyCllEdogEetEsFhitCmblingCngDnyFrabbitCrgessDkeDnsDtonCsalaccDinessDterCtchDlerDtEerGflyEfuckIerEheadEonGsCzzByoungGinCronCtemeCungAc00perB3poBabernetDinboyCctusCdatDcamDweldCesarCipEcadDtlinClebEndarDgaryDibanEfornIiaDlDvinG1CmaroEyDelEraFonDillaGeDlinDpanileEbellEingCnadaDcedFrDdaceEiEyDelaDnonGdaIleDonDtorDucksEteCpfastDtainEianCrbonDdEinalDebearEnEyDlEaEenaEoFsEyleFnDmenDnageDolF1FeGenFieGnaHeFynDrieEolFtEyDsonDterEmanDverDyElEnCscadeHsDeyDhEboxDioDparEerDsieDtleCtalinaFogDch22DfishDherinIeEiEleenEyDnipDsDwomanCyugaBcccEcFcGcHcBecilFeFiaFyCdicClesteDiaEcaEneDticsCmentCnterCrebusDuleanCsarFeDsnaBhadDiEnFsawDkkalaDllengIeDmeleonEpionFsDnEceEdFlerFraHmHsEelFquaEgFeGdGitGmeGthisFhoFkyuEnelFiEshinEtalDoE-yanEfengEsDpmanDrdonnayEgerEityElesFieH1FottIeEmingEonDsDtDuCeckinFovDdsadaDeseGcakeDifDlseaH1DmEistryDnEgDowF-toDralaEryEylDssEterH1DungDvyF1Ci-pangEshunEtaiEwangEyaoDaE-huaFlinFyinGuEraDcagoEkenEoDefsEnDhsingDldsplayEinDnE-wEaFcatEgF-enGliGmeEookEpanDpEperDquitaDshengCldrnDoeCocolatIeDlDongG-hDpEsticksDuEetteCrisF1G23FpenFsGyFtG1GiaInHeHnIaIeGmasGopIhJerGyDonosCuckFyDen-chGtsDnE-linFsheFyuEgF-naGpiGyaFenFyenDongDrchEn-huBiceroCgarCmarronCndelynFrEiEyF1DemaCrcuitDqueDrusCvicElBlaireDmbakeDncyDptonDrenceEisaGsaEkFsonDssFicFrooImDudeGlFiaCeanerFfightFroomEtEvageDoCiffFordEtonDntFonDpperDtEorisCockEloDsefriendDudDverCuelessDsterHsBoatamundiEimundiCbainDraCcacolaEkolaDkDoCdeEnameDyCffeeChenCkacolaDeEisitClbyDdEcutsEshoulderEwarDemanEtteDinDleenFgeFtteEinsDorFadoFsEurDt45EraneDumbiaCmandurDbinationDeEdienneEonEtDmanderEradesEunicationDpaqEtonEuserveFteHrDradeHsCnceptEordeDdoFmGsDfidenEusedDnectFrEieDradDsoleEpirituEultaHiDtentErolDvexCokEieGsFngDlEbeanEmanDperDterCpperCraElynDdeliaDeyDinnaGeDkyDleneDneliaHusEflakeDonaDradoDvetteDwinCsmicEoFsCugarGsDldDntryDplesDrierEtneyDscousCventryCwboyGsDsCyoteBrack1FerDigDppEsDshcourseDwfordCeateFionGveDditDosoteDscentDtinDwCicketDminalDstinaConusDssDwEleyCugDiseDsaderCystalBs-eeCc298D412Die-ciCeeChrcBthreepoDulhuBudaDdlesCervoCnninghamDtCongCpcakeCrmudgeonDrentDtEisCstomerEsupCtdownDieFpieDlassByberFpunkCcloneCnthiaCranoDilAdaddyCebumDdalusDhyunDmonGicGsCggerG1CilyDnDsieEyCkotaCleDiborEtDlasDtryDuCmeDienDmitDogranEnDrongsCnaDceFrDeDgermouseDhDielG1GleDnaEiEyDteCphneDperCqingCrinDk1EmanEstarDrellFnEinEowEylDthFvaderDweiEinDylEouchCshaCtaE1EbaseEtrainDooCveDidF1FoviFsEsCwitDnCytekBdanielrodDyCddEdFdGdHdBe'anCadE-headEaheadEheadGdDnEnaDthFstarCbasishDbieDorahDraCcemberDkerCdheadFdDiCedeeDpakEfreezeEseaFixFpaceEthroatDznutsCfaultDenseDoeCkaiClanoDeteDiverDnazDoisDtaDugeCmeterDoEnFicFsCnaliDisFeDnisEyDverCpecheDtCquinCrekDluenDrekCsareeDertDignEreeDkjetEtopDmondDperateDtinyCtleffDroitCutschCvadminDelopEnDiceElFinsideEneDonCwayneDeyDydecimalCxterBhanDrmaGraCirajBiabloDgEsDlE-inFupEinEupDmondHsDnEaEeEnFeDzCckEensEheadEtracyCegoDselDtEerCggerDitalH1ClbertDipDlweedCmitrisDwitCnaDeshDnerCpakDlomacIyDperDstickDtaCrect1GorDkCscEbrakesEjockeyEoFveryDkDneyCxieDonBoanCctorDumentCdgerGsCesCgbertDcatcherDfightDgieEyCitEnowCllarGsEyDphinHsCmainDenicoDinicHkGqueFoCn'tDaldDeDgEmingDkeyDnEaDtknowCobieDfusDgieDkieDmE2DnDrsCpeyCrabEiDcasDiEsEtDkDothyCubleDdouDgEieElasCwnEtownBr.dementoCaftDgonG1GflIyGsDwDxoDzenCeamFerFsGcapeDwCillpressDnkDppingDverDzztCnoCopE deadEdeadDughtCugnigDmEsCydenBuaneCckEieEsbreathFoupCdeDleyCkeE letoEletoClceCmbassCnbarDcanDdeeDeDgeonsDnCplicateCstinEyCtchFessBvlinsideBwainDneDyneCightBylanAe-mailBachCgerDleF1FsCrlDthCsierDterGnEonDyEcomeEgoElayCtmeDshitHandBckartClipseBddieCenCgarDesCinburghDthCmundCouardCuardGoCwardGsDinFaBe-csCcsCeeEeFeGeHeCyoreBffieBggheadBiderdownCeioCghtCleenCnsteinCrikBkaterinBladioDineDnorCectricDmentDnaEiDphantCiasDna1DotDsabetEsaDzabetIhClaDenDieEotGtEsCmiraDoEotazDstreeCoiseCsieCvinEraEsCwoodDynBmailCeraldCilEeEioEyCmanuelDiEttCoryCpireDtyhandedGeadedBndaEhCemyDrgyCgageDineGerDlandCigmaCriqueCterFpriseDropyCzoDymeBrateaCenityChardCicE1EaEhDkEaDnClingCnestGoDieF1DstCoticCsatzCtyuiopCvanBscortG1CfandiaCmondCpanolCtablishEteDelleDherBtaoinG shrdluGshrdluCeeDrnityChanCoileBuccDlidCgeneCngDjiCropeBvanEsCelynDrafterEyCieBxavierCcaliberHuIrDelEptCploreHrDonentErtDressCtensionCxxtremeByalAfaceDultyCilDrviewEwayEyringDthClconDsestartCmilyG1CncyDgCrahDetheewellDflungDgoneDhadDmerEingDoutDrellDsideDukCsihuddDtEbreakElaneCtanehDboyDcatCustCyeEzBearlessCbruaryCedbackEmeCliciaEksEpeExCnderDrisCreydooDgusGonDmatDrariEetEisBfffEfFfGfHfBictionCdelFityCeldCgaroDleafCleEsystCnanceDdDiteDnConaCreEballFirdEmanEnzeEwalkDstCshE1EerGsFsEheadEieFngDtCtnessCveBlakesDmingoDndersDshCeaDmingDtchGerDursCightDpEperCoatDphouseDresEidaH1DwEerGpotGsDydCuffyDteCyawayDboyDerFsDingGfuckGleapBoghornCngCobarFzDlEproofDtEbalHlCramDbiddenDdDearmEsightFtDkedtoungeDmatDrestDsytheDtuneDwardCsterCulplayDndEtainDrEierEwheelEyearsCxtrotDyladyCzzieBramemakerDnceGsHcIoFineGsHcFoisEkFaFenfurterFieFlinFnfurterDtCeak1FbrothersDdEdieFyEericHkEricDeEbirdEdomEmanDnchG1GfriesDshbreadFmeatCidayDedricEndGsDghtenDscoDtzCodoDgE1EgieHsFyEsDmDnt242FierDshmeatEtyBubarCckE-offFyouEaduckEedFmFrEfaceEingFtElegEmeEoffEuEyouCgaziCllCnctionDgibleEuyDkyDnyDtimeCrballCtureCzbatDzEballGtAgabbyDrielHlDyCdiCelicCgeCilClaEgaExianFyDenDileoCmalDbitElerDesDmaphiCnapathDdalfDjaCoyuanCrciaDdenEnerDfieldEunkelDgoyleDlicDnetDpDrEettEyDthDyCshDmanDtonCtewayH2DorF1DtCussDtamCveEnDrielBedankenCminiCneEralEsisDiusCofEfFreyDrgFeG1FiaGnaCraldErdGoDdDgoryDmanGyH1DonimoDryDtErudeCt fuckedElaidFostEstuffedDfuckedDlaidEostH!EuckyDoutDstuffedBgeorgeCggEgFgGgHgBhandiColamalDstBiancarlEtsCbbonsDsonCffyCgiClbertDgameshDlesDmanCnaDgerGsDoCovanneCridharDlEsCselleCuseppeCveCzmoBlacierDdysCenEdaEeaglesEnCider1CobalDriaBmoneyBnuemacsDsBo awayH!Dfuck yourselfDjump in a lakeDto hellCaheadDlieDtDwayG!CblinEueCcougsCdfleshDivaDzillaCesDtheCfishDoritDuckyourselfChomeCingCjumpinalakeCldEenEfingerGshEieDfEerEingDlumCneDorrheaDzalesHzEoCoberDdE-luckEafternoonEeveningEfightEgriefEjobEluckEmorningEtimesEwifeDfusEyDnightDseCpalonDherDinathCrdanEonDgeousFsDogCslingDonDtraightCtoE hellEhellCugeDldCwestBraceDemeDhamEmDilDmpsDndmaEtDphicHsDtefulIdeadDvisDyEmailCeasyspoonEtDedEnFdayFlineEtingDgE1EgEoryDmlinHsDtaFlEchenEeFlEzkyCiffeyFinDpeDssomDzzlyCoovyDupDverDwCumpyCyphonBsiteBucciCenterDssEtCidoDllermDnnessDtarG1ClukotaCmbyDptionCnnerDtisCozhongCpiCrjotDuCstavoBwenBymnastAh2opoloBackEedFrCfidhDtanCggisChaCiboDleyDrbagGllEilCkanCl9000DlEelujahEoFweenHllDtCmidEltonDletEinDmerGedEondDptonDsterCn-gyooDdilyEwaveHingDkDnaFhDsEelEoloFnEpeteCppeningEyF1G23FdayFendingCrdE2seeEcoreEdiskEiFsonEwareDkaraEonnenDlanEeyG1EotsDmonyDoEldDrietFsGonEoldEyDueEoDvardEeyCsokDsanCttonCuhuaCveDivahCwaiiDkEeyeH1CyesCzelBe'sdeadIjimCalthG1DnDrtFbreakFsDtEherH1H2DvenCbridesCctorCdgehogCeralalDsungCidiDkeEkiDnleinErichEzClenFaFeDgeDlEoF1G23F8FhelloDpE123EerEmeCmantCndersonErixDningDryCrbEertDeDmanEesDnandezDpesDsheyDveDzogCsdeadHjimCungCwlettCydudeDthereBhhhEhFhGhHhBiawathaCberniaCddenCghlandFifeClarieDbertDdaDlEaryEelCroguchEkiEoEshiEyukiCstoireFryCtchcockDhereDlerBoangCbbesEitCckeyG1DusF pocusF-pocusFpocusClaDdDeDidayDlyDyE grailEgrailEshitCmayoumDeEbrewErFjEworkCndaF1DeyDgEkongEphucEtaoDkeyCodlumDkerGsDpsDsierDtersH2011EieCpeDscotchCrizonDnetGsEyDrorDseFsDusCsannaHhDeheadDtCtdogDlipsDrodDtipCucineDseFwifeEtonCwardG93DellDieBplabBsinDuwenCpiceBuangDshengCbbaFhubbaDertCdsonCeyCghEesDoDuesCiyingCmmerCndtDgEmokDterEingCongCrtCsbandDkersEiesDtlerCtchinsCyenCzurBwansooBydrogenFxylCmanConDungCukAi'mokFayBabgBb6ub9CanezCeleiveEieveCmpcFatFxtDsuxCrahimBcapCecreamDmanConBdenticalCiotContknowBf6was9CorgetFotBgnacioEtiusCuanaBhackedDoDteyouCtfpBiiiEiFiGiHiBkonasCuoBlanCmariCoveuFyouCyaBmageEineCbroglioCinCokEayCpactElaDerialCslBncludeCderpalDianGaEgoEraDonesiaDraCfoErmixCgemarDmarDoDresGsEidDvarCheritthewindCigoCnaDocentFuousCsaneDertionDideEghtDtEallEructCtegraHlElErcourseFleafFnGetFracialDoDrepidCvinoveritasEsibleEteCxsBoanaCmegaCngBrelandDneFeCfanCinaDsEhFmanClandeCmaDeliConmanCulianCvingBsaacDbelGleDjokeCelChmaelCidoreDlDsClandCmailCraelDealCsamCtoBt'sajokeEokGayCaliaEyCsajokeDokFayDy-bitsyEbitsyCty-bittyEbittyBuytrewqBvanBzzyAj0kerB1l2t3BackEieG1EolanternEsonDobDquelineGsCdeCegerDjinCggerDuarChanshiCikEneEumarDmeDnCkeEyDovCmaicaDesF1FbondDieElahEsonDjamCnaEkiDeEkElEtDiceEeDnEaEyDuaryDvierDyCpanFeseDonCredCshoEvantDminGeDonF1DpalEerCtinCvedDierCwsCyantaGhDneDsonCzzBeanE-baptisteFclaudeFfrancoisFmichelFpierreFyvesEandaEclaudeEetteEfrancoisEineEmichelEneFieEpierreEyvesCdiCepcjG7EsterCffEeryEreyH1ChanClloEystoneCniferDkinsDnEiFeFferEyF1DsEenCraldDemyDomeDricFmyEyDseyCsseF1EicaFeDterDusF1FchristCthroGhGtullDta1CudiCwelsBiachenDnEliEnEpingEwenChongCkunCllCmboFbDiDminEyCngDshengCongCseongCtendraCxianBjjjEjFjGjHjBkl123D;BnyeBoanEieEnFaFeDquimCcelynCdyCelEleDnaDrgDyChanFnGaH1DnE316ElennonEnyEsonCinE for freeEforfreeCjiDoCkerF1CleCnathanDellEsDgE-iEguDiDnyCrdanG23EieDeanDgeCseEeEphDhEuaDiahEeCurEneyCyceBsbachBuanCbileeCdasDiEantoEcaelEthDyCggleChaniCi-fenDcyDlletDnClayneDesDiEaF2FnGaGnEeF1FnGneFtGteDyCmanjiDboDeauxDpE in a lakeEinalakeCneEbugDgleDiEorEperCpingEterCssiDtEdoitEeEfortheEiceH4FnG1GeCttaBvncAkacyCdoshCkaDogawaCl007DamazoEppaDiDyanEnCngEarooCosCraEleeDenF1DieEnFaFeDlDmaDyEnCseyDhtanCteErinaDherinIeEiEleenEreenFineFynEyDiEeF1EnaDrinaDsufumDydidCvehCylaEenBcinBeciaCepEerEoutDsCithF1CllerFyEyF1DseyCndallDjiDnedyFthEyDobiDtEonDzoCralaDberosDiDmitDnelDriFeEyFaCshavDterCtanDchupCvinF1CwlCyboardDpadBhanEhDyrollCoanhDiDngDsrowCuehF-hoDrsheeBianEgEuschDtCdderDsCeuCllerEmeDroyCmberlyDmoDonCndEerDgEandiEdomEfishElearEsDsonCranDkElandDstenCssEa2EmeCtkatDtenG12GsEyFcatCwiBjhgfdsaBkkkEkFkGkHkBlausCeenexCingonHsBnickersFsDghtGsCowCuteBoalaCichiCjiCkakolaDoCmbatCngjooDradCokCrdaBraigDmerCisEhnaHmEtaFenFiGeGnHaHeFyCystalFynaBurtBwanEgCokDngByahnCeongsoCleCraAlab1DtecCcrosseCddieDiesDleDyEbugCgerCidCkeErsDotaDshmanClitFhGaCmbdaEertDerDinationCnaDceFrDdryCpinCraDissaDkinDryF1DsonCserFjetDsie1DtEangoEtangoCtenightCughDraFeFmaeEelFnGceGtGzEieFndaEyCwrenceDsonDyerCzareFusBeaderDfDhDnnFeCbesgueDlancCd-zeppelinDdzeppelinDzepGpHelinCgalDendErChi3b15CisonEureClandCmonCnaDnonDoreConEardEceEidCroyCsbianDlieDpaulDtatEerCticiaDliveDmeinDoDsgoDterGsCwisCxus1BibertyDraFryCckEerDorneCenDwCfeCghtFsCkeCllianEyDyCmaDitedCncEolnDdaEsayFeyEyDgDhConEelEkingEsCsaDeDpDsabonDtCtterboxEleGhouseGshitIopGtoeCveEandletliveEnletliveErpooIlEsDiaEngCwanaCzaErdDzyBjiljanaBkjasdDhEgFfGdsDlkjBlewellyCllElFlGlHlCoydBmnopBochDkEoutCganDgerDicalEnDosEutCisElaneCkeDiClaDitaDopcCndonDelyEstarDgEcockEerEhairFornErestEtoungeCokDneyDseEingCpezCrenFzoEttaDiEeEnDnaDraineEieDyCserDtCtfiDusF123CuieEsFaFeDnetteDrdesCveElyEmeErFboyFsEyouCwgradeDlifeBpadminBtteBuanaCcasDiaEeFnEferElleDkyF1G4FbreakFladyDyCigiDsDzCkeCluCmiereCnarlanderDdiDeDgCongCtherBydiaEeCleCndonDetteDnEeAm1911a1BaartenCchaEineDintosIhDkDrossDse30EymaCdboyDdieEockFgDeEleineGneFineDhuFsudDisonDmanFxDokaEnnaDyCgdalenDgieEotDicF1EqueDnumChbubaDeshDlonDmoudCiaDdenDlEerEinglistEmanDneEsailEtCjorFdomIoCkeEbreadEdrugsEitGsoEloveEmeFydayEpeaceEwarDingitGloveDotoClcolmFmDibuDlardCnagemeGrEhilDbatDchesterDdyDfredDgeshEueDiEshDoharEjEnDsetmanisEonDtraDuelDyCplesyrupCraEthonDcEelGlaHeHinEhEiFaFoEoEusEyDdiDekDgalitFretGidHtFuxEeFauxEieEoEueriteDiaF1FhG1FnGneEeF-madeleineFlleFttaHeElynEnaFeGrFoEoFnEposaEtialEusDjoryDkE1EetEoEusDlboroEenaGeFyDniDriageEucciDsEhalHlDtEhaFeEiFalFnG1GeHzGienHqEyDvinDyEamFnnEjaneDzecCsahiroDeDh4077DoudDsEcompDterG1GsDuhiroCthE-csEildeDildaDrixDtEherGwFiasGeuEi1FnglyCudeDiDreenEiceGioEoCvericHkCximeEneDmaxDwellHsmartCydayCzda1DinBeaganDtEcleaverEloafEwagonCchEanicCdardDiaEcalCekieCgaEdethEnDgieCisterClaineEnieDinaFdaEsaFsaDlaEonDodyDtinCmberGshipDoryDphisCndelDsuckCowCrcedesFrErediEureGyDdeDesDlinEotDmaidDrellEillEychristmasCtalFlicDroDsCxicoBiamiCchaelH.H1FlEelG1GeGlHeEiganEouEyDkelFyG1EyDroFsoftCdnightDoriDvaleDwayCghtDuelChailDranCkaelDeE1EyDiDkoClanoDdredDesDindDkDlardEeniumFrEicenFeFonDoDtonCmiCndyDeEdErvaDgEheDhDimumDnieDotEuDskyDyeCracleEgeEndaDiamDrorCsanthropeDhaEkaDogynistDsionFrliEyDtyCtchFellDtensBmmmEmFmGmHmCouseBnbvEcFxGzBobileDydickCdelsEmEsteDulaCgensDulFsChamedFmadGedEnCisesEheCjaDoCllyF1DsonGgoldenCndayDetEyF1DiEcaEkaEqueEtorDkeyG1DopolyDroeDsterDtEanaH3EhErealFoseEyCocowDkieDmooDnEbeamEpieDreEhtyDseFheaIdCparCraDeEcatsDganDleyDoniDpheusDrisDtEimerEsCseDheCtherDorFolaEwnCuntainDseF1FmatEumiCviesCwgliCzartBr.rogerCcharlieCgoodbarCwonderfulBt.xinuCichellCxinuBuad-dibEdibDmadinCchCffinChammadCkeshDundClderG1CnaishDchkinDdeepCrphyDrayCscleDicFboxEmDtangH1CtantBycroftxxxHyyyCpasswdHordCraDonDtleCselfDmutCungF-yuAnabilCdegeErDiaEneCftalyCgelCissanceCkamichiCliniCncyDetteComiDtoCpoleonCrcisoGseDendraCsaDcarDtyCtachaEliaGeErajaEshaDhalieFnGaeGieDionGalIeEviteCuticaCveenEtteBcarCc1701HdHeBe1410sE69Ea69CalDrmissCbraskaCckrubCenieCilCkoCllieDsonCmesisCnaCpentheIsDtuneCrmalCsbitGtDsDtleEorCtlinksDmgrDscapeDwareEorkHsCutrinoCvadaDerDilleCwaccountDbloodDcourtDkidGsDlifeDpassDsDtonDuserHsDworldDyorkH1CxtDus6BghiCocCuyenBicaraoDholasGeDkElausDolasFeCelCgelDgerDhtmareFshadowFwalGindChaomaCkeDhilDiEtaDkiDolaosClsonCmhDrodCnaDersDoEnDtendoCrvanaH1CssanEeCtaDeBnnnEnFnGnHnBoamCbodyDuhikoEkoCelCfunCkiaClanCmoreCndetDeE1CpassCraDbertDeenEneDikoDmaFlFnDthwestEonCsecretDhirCtebookEsDgayDhingDreFspassDta1DusedCuveauCvacancyDellEmberGreCwayCxiousBroffBuclearCggetCkeEmCllCmberG1G9GoneGsCrseEieCtmegDritionCucpByquistAoatmealCxacaBbi kenobiEwan kenobiD-wanDwanCsessionBceanFographyDlotCtaviaDoberFreBdetteCileEonBfficeBhshitCwellBicu812CvindBjrindBldladyDpussyCinDveFrFttiEiaFerClieCsenBmeadDgaBnceCionringsClineDyCstadBoooEoFoGoHoCpsBpenEbarEdesktopFoorEsaysmeFesameEupDrEaFtorCusBracleDngeGlineGsCcaDhidCegonDoCgasmCionClandoCvilleCwellBscarCirisCullivaCwaldBtharDerCterDoBu812CssamaCtlawDtolunchBverEkillEthrowFimeBwenCnsBxfordBzzieDyApaagalCcersDificGqueDkardEerGsEratCdaaaDdyDmaDoueCgeCigeDnlessEtFerCkistanCladinDlabDmerDomaCmelaDpersCncakeDdaEoraDicDteraEherEiesCpaDerFsDiersDpasCquesCradigmEllelEnoiaEskevDfaitDisDkEerEinsDolaDrotDtEnerEonDvizCscalDsEionEwdForHdI1IlookhereCtchesDelErneDriceGiaGkFotsDsyDtersonEiEonEyCulEaEeEinGeCvelCwanCymanEentDtonBcatCxtBeaceEhFesDnutGbutterGsDrlFjamCbblesCcheFurHsCdroF1CeblesDweeCgasusDgyCkkaClagieCncilDelopeDguinDisDnyDtecoteEiumEtiCopleDriaCpperDsiCrakaDcolateEyDesEzDfectEormaDryDsimmonEonGaDvertCteErF1FkFpanFsonEyDuniaCugeotDrBgonderinBhamDntomCialphaDlEipGpeGsElipHsDshFyCoenixH1DneDtoCrackDeakDickCyllisBianoF1FmanFsCcardEssoDkEleDtureCerceEreDterCgeonDletCmpCngDkEfloyIdConeerDtrCpelineEorganEr1CrateDieCscesCzzaBlaintruthDneFtDtoDyEboyEerGsEgroundCeaseCierCoverCughDmbrandyDsDtoFnCymouthBocusCeticEryCirEeDssonHsDuEyFtGreClarFbearFisDeDiceEticsDlyDoDynomialCmmeCnderingDtiacCohEbearDkeyEieG1CpcornDeEyeDpyCrcDkEyDnEbayEmanEoFgraphyDscheH9I11J4DterElandEnoyCstelFrCwellErFtoolBpppEpFpGpHpBrabhakaFuEirDdeepDiseDnabDsadEhantDtapEtDvinDyerCeciousDdatorDludeDmierDsenceGtEidentEtoGnDttyGfaceDvisionCiceDmusDnceGssGtonEtFempsGrFingDscaDvEateEsCoducersDfE.EessorEileDgramDmetheIusDnghornDpertyDsperDtectFlEozoaDviderCudenceBsalmsCychoBublicDusCckettCddinCllDsarCmkinpieDpkinCneetDkinCppetEiesEyF123CrnenduDpleCssyF1ByramidDoCthonAq1w2e3BianCnsongBqq111DqEqFqGqHqBualityCebecDenFieDntinDstCocBwaszxCerEtFyG12GuHiAr0gerB2d2BabbitG1CcerFxDhelGleEmaninoffDingDoonCdarDhaDioCfaelDfiDikiCghavGanEuDunathCidEerGsHofthelostarkDmundDnEbowEdropDssaEtlinCjaEdasaDeebFvEndraDivCkeshCleighDphCmachanEnaFiEraoDboF1DeauxEshDirezDonCncidDdalGlEolphFmEyF1DgerGsDjanCoulCptorCquelCscalDtaF1FfarianFmanCtioCvenFsDiCymonaGdBeadEerEingDganDlEfriendEityElyEthingFimeCbeccaElsDootCdbaronErickDcloudDdogDfishDlineDmanDrumDskinHsDwingEoodCebokDdDferCggaeEieDinaGldEonalEsCineCliantCmemberDiDoteDyCnaudFltDeEeEgadeDgarajCplicantDomanEnseDtileDublicCquestEinCscueDearchFuCtardCvolutionCynoldsCzaDnorBhettCinoCjrjlbkConaEdaBiacsCbsCcardoH1DcardoDhEardH1HsIonEmondDkEiEyCddleDeCff-raffErafHfDrafGfCghtCleyCngoCpperEleCscCtaCverFaDiBoadE warriorErunnerEwarriorCbbieEyDertG1GaGoGsDinFhooIdFsonDleyDocopEtFechFicsDynCcheFlleFsterDkEetG1EieEnrollEonEyF horrorF1FhorrorCdentEoDgerDmanDneyDolpheDrigueIzCgerF1FsChitCknyClandGeDexDidexDlinCmainEnFoEricDeoDmelDualdElanHsDyCnakEldDenDiEnEttCokieDsterDtEbeerCpingCsaElieDeEbudElineEmaryEsDieEneDsEignoCthCugeEhDletteDndDte66CxanaDyCyalFsBrrrErFrGrHrBtwoEdtwoBubenDyCdolfDyCeyCfusCgbyDgerEieriCknetClesCnnerEingCoxinCshDsEelGlDtyCthEieElessCyeByanCoheiDtaAsaabE900H0EturboCbbathDinaFeDrinaCcreCdeDieCfaaDetyG1DwatCgittaireCidDfallaDgonDkumarDlingEorDntFeCktiDuraCl9000DahEsanaDesDleEyDmonDomeEneDutCmadamsEnthaDediDiamErDmieEyDpathEleGrEsonDsamEonDtaneyDuelEraiCnchezDdersHonEgorgEiEraFineEsmmxEyDfranHciscoDgEbangEoDhDiDjayEeevEoseH1DtaEiagoFsukEoCphireDphireCraEhF1DojCshaEiDkiaDsyCtoriDurdayFnG5GeGinCulDvignonCvageDeCwedoffCxonBbdcBcamperDrecrowEletHtChemeDnappsDoolDroedeCienceDubbaCoobyGdooEterH1DrpioHnDtEchEtF1FieFyDutFsCreamDofulaEogeDuffyCubaF1DmbagBdfghjklBeabreezeDnDrchDttleCbastienCchangDretG3DurityCekerDmeChoCigneurDveCkharClftimeCmperfiCnditDiorDsorConghooDulCptembeIrHreCquentCrenaFityDgeFiFyDverEiceHsCsameGstreetCthDupCungFhyuFkuCvakDenF7ErinCxfiendDxxmeDyEteenCymourBhadowG1GsEysideDeDggyDhrokhDkespeareDllEomDmitaDnEaEghaiEnanFonFyEtanuFiDolinDradEcEiFynEkFsEleneEonEraDshankFiEtaDunDvedFnDwEnDyneDzamEzamCebaDelaEnaDffieldDilaDlEbyEdonEiaElFeyFyEterDnEgFluDpherdDrifEriGeFyEylCiahnDdanDgenarFoDhEmingDmonDnEobuDpDrinElFeyDtE-headEfacedForbrainsEheadDueDvaFpraEersDzoomCleeDomoCoesDgunDlomDmitaDoterDrtyDtgunDutDwEerEoffCrdluDeeramCuangDhuiDnDtdownEtleCyngBidartaDekickDhartaDneyDoineCemensDrraCgmachiDnalFtureCllywalkDverGeEiaCmbaF1DmonsDonDpleFyEsonHsDsimCnaEtraDgEerEleCobahnCriEusCsterCteCupingCvakumaCxtynineCzenineBkateFrCeeterCibumDdooDingDnnyDpEperH1FyCullDnkCydiveDlerDwalkerBlackerDyerCeazyDepFyCickDderDmeballDnkyDpCusDtBmallFcockFhipsFtalkGipsDshedFingCegmaCileF1FsFyDthFsEtyCokeFdhamFyDochDtherCurfyDtBnafooEuDkeFsDppelGrFleDtchCeezyDllCickerHsDperCoopFdogFyDrkydorkyDwEbalHlEflakeEingEmanEskiCuffyBoapCber1CccerG1EorDrateHsCd offDoffCftEballClangeDeilDomanFonCmanEsamaDbreroDeEbodyCndraDgmiaoEnianDiaEcFsDjaDnyDyEaConEmanDwonCphiaFeEomoreCrelDoorCssinaCtirisCuaDmitraDndDrceEireFsEmilkDvenirBpaceFmanDinDmDnishEkyDrksFyErowHsEtanDzzCecialEterFreDechEdFoFyDnceGrChynxCiceDderGmanDffFyDkeF1DritGuHsanctuEoFsDtEfireClifFfCockDngeDokyElerEnDrtsDtCrangDingGerEteDocketCudDnkyDrsCyrogyraFsBquashDiresFtBridharDmatDnivasBsssEsFsGsHsBtaceyEiFeEyDinlessDlkerDmosDnEislasEleyFyEtonDrE warsE69EbuckEgateElightEsFhipEtFerFrekEwarsDtEesEionEusCealthDelFeGrsDfanGoDllaDmpleDphF1FaneHiIeHyFenFiFonDrlingEn93DveF1FnG1GsFrDwartCickshiftDffdrinkFprickDmpyEulateDngF1FrayEkyDversCocksDneDpDrageEemEmFyCrangeHrGleEtFfordFoGcasterEwberIryDetchDiderDongCtngCuartDdEentH2EfuckEioElyDffedHturkeyDmpyDpidDttgartBubgeniusDhasEdailEednuDodhDscriberDwayCccesGsDkEerEmeErocksEsCdeshnaDhakarEirDirCesecCgarFbearDihCkumarCltanDuCmmerEitDuinenCn-spotDbirdDdanceFyDfireEloweIrDgDilDnyF1FvaleDriseDsetEhinHeDtoolsDweiCperFflyFmanFstageIrFuserFvisorDportHedDraCranetDeshDfEerEingCsanF1FnaGeDhaEilaDieCttonCvenduDroCzannaGeDieDukiDyBvenDrigeBwampratDneEsonCearerEtshopDdenDetieFnesFpeaFsFyCimEmerFingDngsetDtzerCooshDrdfishByamCbaseDilCdneyClvainEereFsteHreEiaFeCmbolDmetryDultCphilisGlisCs5DadmGinDdiagHsDlibDmaintFnEgrDopDtemG5GfiveGvFstDvAt-boneBabathaCcobellCdahiroDlockCffyCiwanCjenCkaEjiEshiDeE5EfiveEiteasyDujiClonCmalEraEsDiEeDmieEyDtamCndyDgerineEoEuyDiaDjuDkerDnerDyaCpaniEsDeCraDdisDgasEetDheelDragonDzanCshaCtaDianaDsuoDtooDumCureauEusCyfurDlorCzdevilDmanGiaBbirdBchenCp-ipD/ipDipBeacherHsDkettleDpartyCchEnicalFoCddiEyF1FbearCenEagerEeyEfanEyCflonClecastFomEphoneDlDnetCmpEoralEtationFressCnnisDtationCquilaCresaDiDminalDreEiFllEyF1CstE1F23E2E3EcaseEerEguyEiFngEtestEuserCtrisDsuoCxasBgifBhaddeusDilandIeDnEasisEhEkFgodFyouDtEcherDvyCeatreDbeefEirdsEossEutlerDcleDendDgreatescapeDirDjudgeDkingHandiDloraxDmEanEonkeyDnDodoraHeEphileDpenguinEroducersDreFalthingFsaGeEiddlerEonDseDyCiamDbaultGtDckcockFheadFskinDerryDlakaDnkEthighsDsEisitCoiDmasEpsonEsonDrneEstenDseCrasherDeeCumperDnderHbIallIirdHdomeDrsdayDyCx1138BianCffanyCgerF2FsDgerDhtassFcuntFendFfitDreCjunCkaCllCmberDeEzoneDothyCnaDgDkerGbellDmanDtinCreswingCtanicDsCzianoBjahjadiBobiasDyCdayDdCgetherDgleChruCkyoClkeinEienCmateFoDcatDmyCneDiDyColDsillyDtsieCpcatDgunDherDographyCrcDnadoDontoDresDstenDtoiseEueCshiakiFbaFterDnowCtalDhedarkDo1EtoCucanDficDrDssaintCveCxicCyotaDsrusBraciFeEtorEyDilblazerFerFsEningDnEsexualFferGigurationFitFmitFportDpdoorEperDshFcanDvailEelEisCeasureDborDeEsDkDntDvorCialDbbleHsDciaEkyDdentDeuDnaDshFaEtanDtonDvialDxieCoffDjanDmboneDnDphyDubleEtDyCucEkFerFsDefriendEloveDmanEpetDstno1CyaBsingF taoF-taoFtaoCungDtomuBtttEtFtGtHtBuanCbaEsCckerDsonCesdayClaDlCnasaladGndwichComasCrboF2DnerEleftErightDtleCttleCyenBwat123CeetheartFyDnexCilaDnsBylerF1BzilaCuwangAudayBhn-soonDsoonBlricFhCtimateBmeshBndeadErgradJuateCguessableChappyCicornFsDformEyDgrafixDqueDtedEyDxE-to-unixHunixEmanEsuckGxCknownDownCtungBpchuckConCperclassCsilonDtillCtohereCyoursBranusCbainCchinCsulaBsenetEixDrE1EmaneEnameEsBtilEityCopiaCpalBucpCuuEuFuGuHuAvacationCderCheClentinIeErieGoDhallaDleyCmpireCnceDessaDillaCrkeyCsantGhDonDsilioCughanBectrexFixCdayDderCljkoDoDvetCnceslasDdrediDetoDiceDkatGadHrGesDtureDusCrilogDmontDnonDonicaGqueDseauDtigeGoDyCteransDteBianneyCbekeDhuDratorCcesquadDkiFeEyDtoireFrG1GiaHenGyCdeoCergeCgyanCjayFaCkingGsDramCllaFgeDmaCnayDceFntH1DitFhaDodFhColetEinCperF1CragoDgilFnGbirthGiaHeHoDusCsaEvisDhvjitDionEtFationForDpiDualDvanatCttorioCvekDianGeEenBjdayBladEimirCsiBmssucksDucksBojinClcanoDleyGbDvoCodooCrtexCyagerBt100C52BvvvEvFvGvHvAwadeCitingCldenEoDeedDidDkEerDleyeEyDterCndaEojoDgDkEerDtEmenowCrcraftDdDezDgamesDlockDmEweatherDnerDrenEiorHsDsDthogCshEingtonCterF1FlooDsonCvesCyneF1BeaselCbetoysDheadDmasteIrDsterCdgeCenieEyDzerCidongDhengDnrichDpingClchEomeH1DlDsherCndelGlEiEyF1DgyikDtCreCsleyDternBhale1FsDtEchamacallitEeveHrEnotEsupHdocCeelingFsDnDreFisthebeefFsthebeefDyCichDskyDtEeEingEneyCocaresDlesaleDopieFyDreDvilleBibbleCckedClburDdcatFhildDfriedDlEenEiamH1HsIburgFeEowEyDmaDsonCn95DdEowGsEsurfDfredDgDnerEieGthepoohDonaDstonDterCredCsconsinDdomDhCthDnessfortheprosecutionCzardGsBojtekClfE1EgangEmanDverinIeFsCmanDbatG1DenCnderGboyHreadDgDyunCobieFnEyDdElandErowEstocEwindEyDfwoofDiyiCpperkennyCrdDkDldDmwoodCuldBqsbBranglerCestleCightDteBuntsinBwwwEwFwGwHwBxyzByldchydCnneComingAx-filesCmenBanaduDthCvierGeBcountryBferCilesBgenerationBiaoEboEgangEliEminCnghaoDuBmodemBrayBueqingBwindowsBxfreessxxCpassxxCsnowxxCx123DxExFxGxHxByz123DzyAyabbaF-dabba-dooFdabbadooCcoCelCmahaCngDjunDkeeGsCominCserBelloFwGstoneCngConEgCziBiannisCgalChuaCngEshaEyangCshunBodaDudeCgeshDibearCichiClandaCmamaCnahDgEdongEhoFwanEsamCsemiteDhiakiFoCu'reokDareokDcefDhanseDngDrEeokEselfBuanCehwernCgangCjiEkoCkaDkeiDonCmiEkoCngCqianCvalBvesDtteConneByyyEyFyGyHyAzacharyDkCpataDhodCryBebraFsCna69DerFdiodeDithCphyrDpelinElinCusExBhaoqianEzhuaCengkunEyanCigangDshunDweiDxinCongguoFminBiggyDzagCmmermanCnfandelCtaCyouBmodemBoltanCmbieCndaComerCranDkEmidDoDroBuluBxc123DvEbFnGmBz-topCtopCzzEzFzGzHz");

    Entropy.CHARSET_RX = {
        lc:  /[a-z]/,                       // lowercase
        uc:  /[A-Z]/,                       // uppercase
        num: /\d/,                          // numbers
        sp:  /\u0020/,                      // A regular space character

        non_keyboard: /[^\u0020-\u007E]/,   // non-keyboard symbols
        non_alpha: /[^a-zA-Z]/,             // non-alpha characters

        sym_upper: /[~`!@#$%^&*()\-_+=]/,   // upper keyboard symbols
        sym_lower: /[[{\]}\\|;:'",<.>/?]/   // lower keyboard symbols
    };


    /* ########################################################### */
    /*                     PRIVATE FUNCTIONS                       */
    /* ########################################################### */

    /**
     * @private
     * Convert the "packed" version of the dictionary list to a hash for easy word lookups
     * @param wl {String} A string whose uppercase characters separate the words and represent
     *      how many characters to duplicate from the previous word in the string.
     * @return {Object}
     */
    function unpackDictList(wl) {
        var rx = /([A-Z])([^A-Z]+)/g,
            match,
            word = '',
            dict = {},
            acc = 'A'.charCodeAt(0);

        while ((match = rx.exec(wl)) != null) {
            word = word.substring(0, match[1].charCodeAt(0)-acc) + match[2];
            dict[word] = true;
        }
        return dict;
    }


})();




/**
 * @constructor
 * @class PWStrengthMeter
 *
 * @param fieldEl {HTMLInput} The password field whose "onkeyup" event will be monitored.
 *
 * @param meterEl {HTMLElement} The password strength meter element whose className attribute will be updated
 *      based on the status (valid or invalid) and range (weak, good, or strong) of the password.
 *
 * @param opts {Object} Optional configuration arguments that can be passed in to tailor the functionality of
 *      the class.
 *
 *      @config onChange {function} Listener to call whenever the password is changed. Returning false will
 *          cancel the setting of classNames on the meterEl. The function will be passed an object with the
 *          following attributes:
 *          {
 *              valid: < Boolean indicating whether the password passed all of the rules >,
 *              range:  < Object of range that the password matched >,
 *              invalidRules: < Array of the rules that failed to validate. Empty if valid is true >
 *          }
 *
 *      @config ranges {Object[]} An array of range objects that define a minimum and maximum number for a range that
 *          the password's calculated bits that will be compared against to determine if they fit in the given range.
 *          The cls attribute will be applied to the meterEl whenever the rule matches the calculated bitRange.
 *          The default ranges are:
 *          [
 *              { min: Number.NEGATIVE_INFINITY, max: 56, cls: "weak"},
 *              { min: 56, max: 80, cls: "good" },
 *              { min: 80, max: Number.POSITIVE_INFINITY, cls: "strong" }
 *          ]
 *
 *      @config rules {Object[]} An array of rule objects that will be tested agains the password.  Each rule object must
 *          have a "regex" attribute that will be tested via "regex.test(password)" and compared to the "result"
 *          boolean attribute to determine whether the rule has been successfully fulfilled. Default is no rules (ie []).
 *          Example of an array of rules:
 *          [
 *              {regex: /.{8,}/, result: true },   // length >= 8
 *              {regex: /[a-z]/i, result: true },  // Must contain at least one alpha character
 *              {regex: /[\W_]/, result: true },   // Must contain one symbol
 *              {regex: /^\d/, result: false }     // Cannot start with a number
 *          ]
 *
 *      @config clsValid {String} Optional class added to meterEl when the password is valid. Default is "valid".
 *
 *      @config clsInvalid {String} Optional class added to meterEl when the password is invalid. Default is "invalid".
 *
 * }
 *
 */
var PWStrengthMeter = function (fieldEl, meterEl, opts) {
    var o;

    this.fieldEl = fieldEl;
    this.meterEl = meterEl;

    if (typeof opts == "object") {
        for (o in opts) {
            if (o in this) { this[o] = opts[o]; }
        }
    }

    // Add onkeyup listener to password field
    var fn = this.checkField.curry(this);
    if (fieldEl.addEventListener) {
        fieldEl.addEventListener('keyup', fn, false);
    } else if (fieldEl.attachEvent) {
        fieldEl.attachEvent('onkeyup', fn);
    }

    // Initialize the password strength meter
    this.checkField();
};


PWStrengthMeter.prototype = {

    fieldEl: null,
    meterEl: null,
    password: null,

    // opts
    ranges: [
        { min: Number.NEGATIVE_INFINITY, max: 0, cls: "empty"},
        { min: 0, max: 56, cls: "weak"},
        { min: 56, max: 80, cls: "good" },
        { min: 80, max: Number.POSITIVE_INFINITY, cls: "strong" }
    ],

    onChange: null,
    rules: [],
    clsValid: "valid",
    clsInvalid: "invalid",
    // eo opts


    checkField: function () {
        var entropyObj;

        // check if the password changed before proceeding
        if (this.fieldEl.value !== this.password) {
            // password has changed
            this.password = this.fieldEl.value;
            entropyObj = new Entropy(this.password);
            this.notify(entropyObj);
        };
    },


    /*
     * Callback function for whatever method we called to calculate the strength
     * of the password. Currently, we are using the Entropy Class to calculate
     * the bit strength of the given password.
     * @param info {Object} Data about the given password. Example Object would be:
     *          {
     *              password: "test",
     *              length: 4,
     *              bits: .224208765,
     *              entropy: 22.4,
     *              inDict: true,
     *              charset: { size: 128, count: 3 }
     *          }
     *
     * @return data {Object} Data associated with the password: validity, rules broken, ranges.
     */
    notify: function (info) {
        var data = {valid:true, invalidRules:[], range:null},
            i,
            rl,
            range,
            pw = info.password,
            entropy = info.entropy,
            cancelCSS = false,
            mel = this.meterEl,
            cls;


        // Check the validity of the password by testing it against all of the rules
        for (i=0; i<this.rules.length; ++i) {
            rl = this.rules[i];
            if (rl.regex.test(pw) === !(rl.result === false)) {
                continue;  // nothing to do if valid
            } else {
                data.invalidRules[data.invalidRules.length] = this.clone(rl);
                data.valid = false;
            }
        }

        if (data.valid) {
            delete data.invalidRules
        }

        // Determine what "ranges" the password is based on it's bit value
        for (i=0; i<this.ranges.length; ++i) {
            range = this.ranges[i];
            if (entropy >= range.min && entropy <= range.max) {
                data.range = range;
                break;
            }
        }

        if (typeof this.onChange == "function") {
            cancelCSS = (this.onChange(data)===false);
        }

        if (!cancelCSS) {

            // Add the appropriate CSS classes to the meterEl based on the current
            // status of the password.
            this.removeClass( mel, (data.valid ? this.clsInvalid : this.clsValid));
            this.addClass( mel, (data.valid ? this.clsValid : this.clsInvalid));

            this.addClass(mel, range.cls||"");
            for (i=0; i<this.ranges.length; ++i) {
                cls = this.ranges[i].cls;
                if (cls != data.range.cls) {
                    this.removeClass(mel, cls)
                }
            }
        }

    },


    /**
     * Make a shallow copy of an object. The copy is NOT recursive (i.e. it is only one level deep).
     */
    clone: function (obj) {
        if (typeof obj != 'object'){
            return obj;
        }

        var newObj = {};
        for (var i in obj) {
            newObj[i] = obj[i];
        }
        return newObj;
    },

    addClass: function (el, cls) {
        var clsNms, ln, i;

        if ( el.nodeType === 1 && typeof cls === "string" ) {
            clsNms = (el.className || "").split( /\s+/ );
            ln=clsNms.length;
            for (i=0; i<ln; ++i) {
                if (clsNms[i] == cls) { return;  } // nothing to do if we find a matching classname
            }
            // Add the class
            clsNms[ln] = cls;
            el.className = clsNms.join(" ");
        }
    },

    removeClass: function (el, cls) {
        var clsNms, ln, i;

        if ( el.nodeType === 1 && typeof cls === "string" ) {
            clsNms = (el.className || "").split( /\s+/ );
            ln=clsNms.length;
            for (i=0; i<ln; ++i) {
                if (clsNms[i] == cls) {
                    clsNms.splice(i,1);
                    el.className = clsNms.join(" ");
                    return;
                }
            }
        }
    }

};


/**
 * Augment Function.prototype to give functions the ability to generate
 * closures with pre-defined scope and arguments. curry() MUST be called
 * as a method, ex.
 *      myFunction.curry();
 * NOT as a regular function, ex.
 *      var a = myFunction.curry; a();
 *
 * @param scope {Object} What the value of "this" will be when the function is called.
 *          Default is the Window object.
 * @param arguments {Any} Any arguments, after the scope, will be appended, as arguments,
 *          when the function is called.
 * @return {Function} A function that, when called, will have the pre-defined scope and
 *          arguments.
 */
if(!Function.prototype.curry) {
    (function () {
        var slice = Array.prototype.slice;

        Function.prototype.curry = function (scope /* arg_1, arg_2, ... arg_N */) {

            if (typeof this != "function") {
                throw {name: "TypeError", message: "curry must be called as a method"}
            }

            var args = slice.call(arguments, 1),
                fn = this;

            return function ( ) {
                fn.apply(scope||this, slice.call(arguments).concat(args));
            };
        } // -- eo curry method

    })();
}

